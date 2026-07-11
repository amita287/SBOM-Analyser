"""Load and validate the data files (Phase 2).

Every loader reads one file from ``data/`` and validates **every** row against
the Section 4 Pydantic schemas in :mod:`sbom_analyzer.models.entities`. A single
bad row raises :class:`DataValidationError` — nothing is silently skipped or
coerced away. This is the analyzer's only entry point to disk.

The ground-truth ``dependency_labels.csv`` is deliberately *not* loadable here:
it is eval-only. The analyzer must never see the labels, or the "detection"
metrics become a tautology. Only the Phase 8 eval harness reads that file, with
its own loader. The name is recorded below purely so the exclusion is explicit
and greppable.
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
    Vulnerability,
)

# --------------------------------------------------------------------------- #
# File names (Section 4)
# --------------------------------------------------------------------------- #
APPLICATIONS_FILE = "applications.json"
DEPENDENCIES_FILE = "sbom_dependencies.csv"
VULNERABILITIES_FILE = "vulnerability_db.json"
LICENSE_RULES_FILE = "license_rules.json"

# EVAL-ONLY ground truth — the analyzer pipeline must NEVER read this file.
# It is loaded only by the Phase 8 eval harness, with its own loader.
LABELS_FILE_EVAL_ONLY = "dependency_labels.csv"


class DataValidationError(ValueError):
    """A data-file row failed schema validation.

    Raised loudly and immediately — the loaders never skip a bad row, so a
    malformed dataset stops the pipeline instead of quietly shrinking it.
    """


@dataclass(frozen=True)
class Dataset:
    """The four analyzer-visible inputs, all validated. No labels here."""

    applications: list[Application]
    dependencies: list[Dependency]
    vulnerabilities: list[Vulnerability]
    license_rules: LicenseRules


# --------------------------------------------------------------------------- #
# Low-level helpers
# --------------------------------------------------------------------------- #
def _read_json(path: Path) -> Any:
    if not path.is_file():
        raise FileNotFoundError(f"required data file missing: {path}")
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def _validate_row(
    model: type[BaseModel], raw: Any, *, source: str, index: int
) -> Any:
    """Validate one record, re-raising with file + row context on failure."""
    try:
        return model.model_validate(raw)
    except ValidationError as exc:
        raise DataValidationError(
            f"{source}: record {index} failed validation for "
            f"{model.__name__}:\n{exc}"
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
    """4.1 — ``applications.json`` (JSON array of application records)."""
    data_dir = Path(data_dir)
    raw = _require_json_array(
        _read_json(data_dir / APPLICATIONS_FILE), source=APPLICATIONS_FILE
    )
    return [
        _validate_row(Application, row, source=APPLICATIONS_FILE, index=i)
        for i, row in enumerate(raw)
    ]


def load_dependencies(data_dir: Path | str) -> list[Dependency]:
    """4.2 — ``sbom_dependencies.csv`` (one row per occurrence)."""
    data_dir = Path(data_dir)
    path = data_dir / DEPENDENCIES_FILE
    if not path.is_file():
        raise FileNotFoundError(f"required data file missing: {path}")

    expected = set(Dependency.model_fields)
    deps: list[Dependency] = []
    with path.open("r", encoding="utf-8", newline="") as fh:
        reader = csv.DictReader(fh)
        header = set(reader.fieldnames or [])
        if header != expected:
            missing = sorted(expected - header)
            extra = sorted(header - expected)
            raise DataValidationError(
                f"{DEPENDENCIES_FILE}: header mismatch — "
                f"missing={missing}, unexpected={extra}"
            )
        for i, row in enumerate(reader):
            deps.append(
                _validate_row(Dependency, row, source=DEPENDENCIES_FILE, index=i)
            )
    return deps


def load_vulnerabilities(data_dir: Path | str) -> list[Vulnerability]:
    """4.3 — ``vulnerability_db.json`` (JSON array of advisories)."""
    data_dir = Path(data_dir)
    raw = _require_json_array(
        _read_json(data_dir / VULNERABILITIES_FILE), source=VULNERABILITIES_FILE
    )
    return [
        _validate_row(Vulnerability, row, source=VULNERABILITIES_FILE, index=i)
        for i, row in enumerate(raw)
    ]


def load_license_rules(data_dir: Path | str) -> LicenseRules:
    """4.4 — ``license_rules.json`` (single object, licenses + compatibility)."""
    data_dir = Path(data_dir)
    raw = _read_json(data_dir / LICENSE_RULES_FILE)
    try:
        return LicenseRules.model_validate(raw)
    except ValidationError as exc:
        raise DataValidationError(
            f"{LICENSE_RULES_FILE}: failed validation for LicenseRules:\n{exc}"
        ) from exc


# --------------------------------------------------------------------------- #
# Bundle
# --------------------------------------------------------------------------- #
def load_dataset(data_dir: Path | str | None = None) -> Dataset:
    """Load and validate all four analyzer-visible files.

    Defaults to the configured ``data_dir``. Never touches the eval-only
    ``dependency_labels.csv``.
    """
    resolved = Path(data_dir) if data_dir is not None else get_settings().data_dir
    return Dataset(
        applications=load_applications(resolved),
        dependencies=load_dependencies(resolved),
        vulnerabilities=load_vulnerabilities(resolved),
        license_rules=load_license_rules(resolved),
    )
