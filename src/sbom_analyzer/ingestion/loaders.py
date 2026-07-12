"""Load and validate the data files.

Every loader reads one file from ``data/`` and validates **every** row against
the Pydantic schemas in :mod:`sbom_analyzer.models.entities`. A single bad row
raises :class:`DataValidationError` — nothing is silently skipped or coerced
away. This is the analyzer's only entry point to disk.

The ground-truth ``dependency_labels.csv`` is deliberately *not* loadable here:
it is eval-only. The analyzer must never see the labels, or the "detection"
metrics become a tautology. Only the eval harness reads that file, with its own
loader. The name is recorded below purely so the exclusion is explicit and
greppable.
"""

from __future__ import annotations

import csv
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ValidationError

from sbom_analyzer.config import get_settings
from sbom_analyzer.models.entities import (
    Application,
    Dependency,
    LicenseRules,
    TransitiveEdge,
    Vulnerability,
)

APPLICATIONS_FILE = "applications.json"
DEPENDENCIES_FILE = "sbom_dependencies.csv"
TRANSITIVE_FILE = "transitive_dependencies.json"
VULNERABILITIES_FILE = "vulnerability_db.json"
LICENSE_RULES_FILE = "license_rules.json"

# EVAL-ONLY ground truth — the analyzer pipeline must NEVER read this file.
LABELS_FILE_EVAL_ONLY = "dependency_labels.csv"


class DataValidationError(ValueError):
    """A data-file row failed schema validation.

    Raised loudly and immediately — the loaders never skip a bad row, so a
    malformed dataset stops the pipeline instead of quietly shrinking it.
    """


@dataclass(frozen=True)
class Dataset:
    """The analyzer-visible inputs, all validated. No labels here."""

    applications: list[Application]
    dependencies: list[Dependency]
    vulnerabilities: list[Vulnerability]
    license_rules: LicenseRules
    transitive_edges: list[TransitiveEdge]


# --------------------------------------------------------------------------- #
# Low-level helpers
# --------------------------------------------------------------------------- #
def _read_json(path: Path) -> Any:
    if not path.is_file():
        raise FileNotFoundError(f"required data file missing: {path}")
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def _validate_row(model: type[BaseModel], raw: Any, *, source: str, index: int) -> Any:
    try:
        return model.model_validate(raw)
    except ValidationError as exc:
        raise DataValidationError(
            f"{source}: record {index} failed validation for {model.__name__}:\n{exc}"
        ) from exc


def _require_json_array(raw: Any, *, source: str) -> list[Any]:
    if not isinstance(raw, list):
        raise DataValidationError(
            f"{source}: expected a top-level JSON array, got {type(raw).__name__}"
        )
    return raw


# --------------------------------------------------------------------------- #
# Per-file loaders
# --------------------------------------------------------------------------- #
def load_applications(data_dir: Path | str) -> list[Application]:
    raw = _require_json_array(
        _read_json(Path(data_dir) / APPLICATIONS_FILE), source=APPLICATIONS_FILE
    )
    return [
        _validate_row(Application, row, source=APPLICATIONS_FILE, index=i)
        for i, row in enumerate(raw)
    ]


# Required CSV columns. Validated as a subset, not an exact set: an SBOM export
# gaining a column is no reason to refuse to run — losing one is.
DEPENDENCY_COLUMNS = {
    "dep_id",
    "application_id",
    "library",
    "version",
    "license",
    "dependency_type",
    "last_updated",
}


def load_dependencies(data_dir: Path | str) -> list[Dependency]:
    path = Path(data_dir) / DEPENDENCIES_FILE
    if not path.is_file():
        raise FileNotFoundError(f"required data file missing: {path}")

    deps: list[Dependency] = []
    with path.open("r", encoding="utf-8", newline="") as fh:
        reader = csv.DictReader(fh)
        header = set(reader.fieldnames or [])
        missing = sorted(DEPENDENCY_COLUMNS - header)
        if missing:
            raise DataValidationError(
                f"{DEPENDENCIES_FILE}: header is missing required column(s): "
                f"{missing}. Found: {sorted(header)}"
            )
        for i, row in enumerate(reader):
            deps.append(
                _validate_row(Dependency, row, source=DEPENDENCIES_FILE, index=i)
            )
    return deps


def load_transitive_edges(data_dir: Path | str) -> list[TransitiveEdge]:
    path = Path(data_dir) / TRANSITIVE_FILE
    # Optional: the same edges ride along on each dependency row's
    # `transitive_deps` column, so a dataset without this file is still complete.
    if not path.is_file():
        return []
    raw = _require_json_array(_read_json(path), source=TRANSITIVE_FILE)
    return [
        _validate_row(TransitiveEdge, row, source=TRANSITIVE_FILE, index=i)
        for i, row in enumerate(raw)
    ]


def load_vulnerabilities(data_dir: Path | str) -> list[Vulnerability]:
    raw = _require_json_array(
        _read_json(Path(data_dir) / VULNERABILITIES_FILE), source=VULNERABILITIES_FILE
    )
    return [
        _validate_row(Vulnerability, row, source=VULNERABILITIES_FILE, index=i)
        for i, row in enumerate(raw)
    ]


def load_license_rules(data_dir: Path | str) -> LicenseRules:
    raw = _read_json(Path(data_dir) / LICENSE_RULES_FILE)
    rules = _require_json_array(raw, source=LICENSE_RULES_FILE)
    try:
        return LicenseRules.model_validate({"rules": rules})
    except ValidationError as exc:
        raise DataValidationError(
            f"{LICENSE_RULES_FILE}: failed validation for LicenseRules:\n{exc}"
        ) from exc


# --------------------------------------------------------------------------- #
# Bundle
# --------------------------------------------------------------------------- #
def _cross_check_edges(
    dependencies: list[Dependency], edges: list[TransitiveEdge]
) -> None:
    """The edge list appears twice in this dataset. Check it agrees with itself.

    ``transitive_dependencies.json`` and the ``transitive_deps`` CSV column
    describe the same 372 edges. Redundant inputs that quietly disagree are a
    classic source of "the graph is subtly wrong and nobody noticed", so compare
    them and fail loudly rather than picking a winner behind the user's back.
    """
    if not edges:
        return

    from_csv = {
        (d.app_id, d.library_name, d.version, c.library_name, c.version)
        for d in dependencies
        for c in d.transitive_children
    }
    from_json = {
        (e.app_id, e.parent_library, e.parent_version, e.child_library, e.child_version)
        for e in edges
    }
    if from_csv != from_json:
        raise DataValidationError(
            f"{TRANSITIVE_FILE} and {DEPENDENCIES_FILE}:transitive_deps disagree "
            f"({len(from_csv)} CSV edges vs {len(from_json)} JSON edges). "
            f"Only in CSV: {sorted(from_csv - from_json)[:3]}. "
            f"Only in JSON: {sorted(from_json - from_csv)[:3]}."
        )


def load_dataset(data_dir: Path | str | None = None) -> Dataset:
    """Load and validate every analyzer-visible file.

    Defaults to the configured ``data_dir``. Never touches the eval-only
    ``dependency_labels.csv``.
    """
    resolved = Path(data_dir) if data_dir is not None else get_settings().data_dir

    dependencies = load_dependencies(resolved)
    edges = load_transitive_edges(resolved)
    _cross_check_edges(dependencies, edges)

    return Dataset(
        applications=load_applications(resolved),
        dependencies=dependencies,
        vulnerabilities=load_vulnerabilities(resolved),
        license_rules=load_license_rules(resolved),
        transitive_edges=edges,
    )
