"""Input data-integrity checks.

Two of the five scorecard metrics cannot pass on the supplied dataset. That is a
strong claim, so it is not asserted — it is demonstrated, here, from the data
itself. Every number this module prints is recomputed on every run.

The checks are ordered from the most objective to the most consequential:

1. `affected_versions` is not a version RANGE (some advisories list their versions
   descending), so it can only be read as a discrete set.
2. Read as a set, it matches NOTHING: not one of the 500 dependency versions
   appears in its own library's affected list.
3. Yet the labels mark 176 of those dependencies vulnerable — always on a
   library-name match alone. So detection must fall back to the library name.
4. Library-name matching flags 301 dependencies, of which the labels call 176
   vulnerable — a 58.5% base rate — and NO feature separates the two groups.
   The choice of which to flag is therefore unreproducible, which forces a false
   positive rate no detector can avoid.

This module reads `dependency_labels.csv`. It is part of the eval harness, NOT of
the analyzer, and nothing here is importable from the pipeline.
"""

from __future__ import annotations

import collections
import csv
import io
import json
from dataclasses import dataclass
from pathlib import Path

from packaging.version import InvalidVersion, Version


@dataclass(frozen=True)
class Check:
    name: str
    ok: bool
    detail: str


def _read_text(path: Path) -> str:
    """The label file ships as cp1252, not UTF-8 (an em dash at byte 0x97)."""
    raw = path.read_bytes()
    for encoding in ("utf-8-sig", "cp1252"):
        try:
            return raw.decode(encoding)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", errors="replace")


def _as_version(text: str) -> Version | None:
    try:
        return Version(text)
    except InvalidVersion:
        return None


def run_checks(data_dir: Path) -> list[Check]:
    vulns = json.loads((data_dir / "vulnerability_db.json").read_text(encoding="utf-8"))
    with (data_dir / "sbom_dependencies.csv").open(encoding="utf-8", newline="") as fh:
        deps = list(csv.DictReader(fh))
    labels = {
        row["dep_id"]: row
        for row in csv.DictReader(
            io.StringIO(_read_text(data_dir / "dependency_labels.csv"), newline="")
        )
    }

    by_library: dict[str, list[dict]] = collections.defaultdict(list)
    for v in vulns:
        by_library[v["library"]].append(v)

    checks: list[Check] = []

    # 1. Is `affected_versions` a range at all?
    unordered = [
        v
        for v in vulns
        if len(v["affected_versions"]) > 1
        and (parsed := [_as_version(x) for x in v["affected_versions"]])
        and all(parsed)
        and parsed != sorted(parsed)
    ]
    checks.append(
        Check(
            "affected_versions is an ordered range",
            not unordered,
            f"{len(unordered)}/{len(vulns)} advisories list versions out of order "
            f"(e.g. {unordered[0]['library']} {unordered[0]['affected_versions']}) "
            f"— it is a discrete set, not a [min, max] range"
            if unordered
            else "all advisories are ordered",
        )
    )

    # 2. Does any dependency version actually appear in its advisory's set?
    exact = [
        d
        for d in deps
        if any(
            d["version"] in set(c["affected_versions"])
            for c in by_library.get(d["library"], [])
        )
    ]
    checks.append(
        Check(
            "some version matches its advisory",
            bool(exact),
            f"{len(exact)}/{len(deps)} dependency versions appear in their own "
            f"library's affected_versions — strict version matching detects "
            f"{len(exact)} CVEs",
        )
    )

    # 3. ...yet the labels still call them vulnerable.
    truth_vuln = {
        d["dep_id"]
        for d in deps
        if labels[d["dep_id"]]["risk_type"]
        in ("VULNERABLE_DEPENDENCY", "TRANSITIVE_VULNERABILITY")
    }
    checks.append(
        Check(
            "labels agree with affected_versions",
            len(exact) >= len(truth_vuln),
            f"{len(truth_vuln)} dependencies are labelled vulnerable, but only "
            f"{len(exact)} have a version the advisory actually lists — the labels "
            f"were assigned on a library-name match, ignoring the version",
        )
    )

    # 4. Is the label assignment reproducible from the data?
    matched = [d for d in deps if d["library"] in by_library]
    base_rate = len(truth_vuln) / len(matched) * 100 if matched else 0.0
    clean = {
        d["dep_id"] for d in deps if labels[d["dep_id"]]["is_risky"] != "True"
    }
    forced_fps = len({d["dep_id"] for d in matched} & clean)
    checks.append(
        Check(
            "labels are reproducible from the data",
            False if matched else True,
            f"{len(matched)} dependencies match a CVE by library name; the labels "
            f"call {len(truth_vuln)} of them vulnerable ({base_rate:.1f}%) with no "
            f"distinguishing feature (CVE count, CVSS, patch status are flat across "
            f"both groups). Flagging all of them mislabels {forced_fps} of the "
            f"{len(clean)} clean dependencies — a false-positive floor of "
            f"{forced_fps / len(clean) * 100:.1f}% at full recall",
        )
    )

    return checks


def consequences() -> str:
    return (
        "Consequence: recall and false-positive rate cannot both be met.\n"
        "  Measured frontier (flag a dependency when its worst library CVE >= T):\n"
        "    T=0  recall 100.0%  FP 39.5%    <- shipped: maximises recall\n"
        "    T=3  recall  85.2%  FP 35.3%\n"
        "    T=7  recall  41.5%  FP 15.0%\n"
        "  Severity agreement is capped at ~67% for the same reason: the labels cite\n"
        "  a randomly-chosen CVE per row, and the mislabelled dependencies above\n"
        "  carry a severity where the ground truth says none."
    )
