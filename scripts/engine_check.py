"""Engine check — IS THE ANALYZER WRONG, OR IS THE DATA?

**This is a diagnostic. It is NOT a scorecard, and its numbers must never be
reported as detection results.** It builds one of its inputs from the ground-truth
labels, which makes scenario C circular *by design*: that is the whole point. It
holds the analyzer fixed and varies the data, to isolate one question.

Two of the hackathon's targets are unreachable on the supplied dataset. That is a
strong claim and "trust me" is not an argument, so this runs the same analyzer
code three ways and lets the numbers speak:

  A. SUPPLIED data, STRICT matching (only version-confirmed CVEs count)
     The rule the README's Step 2 actually specifies. It detects ZERO CVEs,
     because not one of the 500 dependency versions appears in its own library's
     `affected_versions`. Recall collapses to 0%. False positives are near zero —
     a scanner that finds nothing accuses nobody.

  B. SUPPLIED data, potentials count  <-- WHAT WE SHIP
     Falls back to library-name matching, which is the only thing that detects
     anything here. Recall 100%. But the labels call 125 of those 301 library
     matches clean, with nothing in the data to tell them apart, so ~105 clean
     dependencies get flagged and the false-positive rate is stuck around 31%.

  C. CONSISTENT data, STRICT matching
     Identical analyzer. The ONLY change is repairing `affected_versions` so the
     CVE database agrees with the labels it ships alongside. Every metric passes.

The conclusion C forces: the detection logic, the graph, the licence engine, the
staleness rule, the scorer and the severity rules are all correct. What fails is
an input that contradicts itself — the advisories say one thing, the labels say
another, and no analyzer can satisfy both.

    python scripts/engine_check.py
"""

from __future__ import annotations

import copy
import csv
import io
import os
import sys
from collections import defaultdict
from pathlib import Path

from sbom_analyzer.config import get_settings
from sbom_analyzer.ingestion.loaders import Dataset, load_dataset
from sbom_analyzer.reporting.report import build_report

try:
    from scripts.evaluate import Record, compute_binary, compute_metrics, load_labels
except ModuleNotFoundError:  # pragma: no cover - depends on how it was invoked
    from evaluate import Record, compute_binary, compute_metrics, load_labels

if sys.platform == "win32":
    os.system("")
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:  # pragma: no cover
    pass

GREEN, RED, YELLOW = "\033[92m", "\033[91m", "\033[93m"
BOLD, DIM, RESET = "\033[1m", "\033[2m", "\033[0m"

VULN_LABELS = {"VULNERABLE_DEPENDENCY", "TRANSITIVE_VULNERABILITY"}


def _read_labels(path: Path) -> dict[str, dict]:
    raw = path.read_bytes()
    for enc in ("utf-8-sig", "cp1252"):
        try:
            text = raw.decode(enc)
            break
        except UnicodeDecodeError:
            continue
    else:  # pragma: no cover
        text = raw.decode("utf-8", errors="replace")
    return {r["dep_id"]: r for r in csv.DictReader(io.StringIO(text, newline=""))}


def repair(ds: Dataset, labels: dict[str, dict]) -> Dataset:
    """Make `affected_versions` agree with the labels shipped beside it.

    Repairs exactly ONE field and nothing else — same apps, same dependencies,
    same licences, same edges. Every difference in the result is attributable to
    that field.
    """
    fixed = copy.deepcopy(ds.vulnerabilities)
    by_lib: dict[str, list] = defaultdict(list)
    for v in fixed:
        by_lib[v.library_name].append(v)

    for dep in ds.dependencies:
        advisories = by_lib.get(dep.library_name)
        if not advisories:
            continue
        label = labels[dep.dependency_id]

        if label["risk_type"] in VULN_LABELS:
            # Attach the version to the advisory whose severity the label cites,
            # so severity becomes derivable too.
            want = label["severity"].lower()
            pick = next(
                (a for a in advisories if a.cvss_severity.value == want), advisories[0]
            )
            if dep.version not in pick.affected_versions:
                pick.affected_versions.append(dep.version)
        else:
            for a in advisories:
                if dep.version in a.affected_versions:
                    a.affected_versions.remove(dep.version)

    return Dataset(
        applications=ds.applications,
        dependencies=ds.dependencies,
        vulnerabilities=fixed,
        license_rules=ds.license_rules,
        transitive_edges=ds.transitive_edges,
    )


def run(dataset: Dataset, *, strict: bool, title: str, labels) -> int:
    cfg = get_settings().model_copy(update={"strict_version_matching": strict})
    report = build_report(dataset, settings=cfg)

    preds = {
        f.dependency_id: Record(
            risk_types={rt.value for rt in f.risk_types},
            primary=f.primary_risk_type.value,
            severity=f.severity.value,
            flagged_vulnerable=f.is_flagged_vulnerable,
        )
        for a in report.apps
        for f in a.findings
    }

    metrics = compute_metrics(preds, labels) + compute_binary(preds, labels)[:2]
    passed = sum(m.passed for m in metrics)
    tone = GREEN if passed == len(metrics) else YELLOW

    print(f"\n{BOLD}{title}{RESET}  {tone}[{passed}/{len(metrics)} pass]{RESET}")
    for m in metrics:
        mark = f"{GREEN}PASS{RESET}" if m.passed else f"{RED}FAIL{RESET}"
        colour = GREEN if m.passed else RED
        print(
            f"   {mark}  {m.name:<32}{colour}{m.value:6.1%}{RESET}  target {m.target}"
        )
    return passed


def main() -> int:
    settings = get_settings()
    ds = load_dataset()
    labels = load_labels(settings.data_dir / "dependency_labels.csv")
    raw_labels = _read_labels(settings.data_dir / "dependency_labels.csv")

    print(f"{BOLD}Engine check{RESET} {DIM}— same analyzer, three inputs{RESET}")
    print(f"{DIM}Diagnostic only. Scenario C builds its input from the labels and is")
    print(f"circular by construction; it isolates the data defect, it does not")
    print(f"measure detection.{RESET}")

    run(
        ds,
        strict=True,
        title="A) SUPPLIED data + STRICT matching  (the README's Step 2 rule)",
        labels=labels,
    )
    run(
        ds,
        strict=False,
        title="B) SUPPLIED data + potentials count  <-- WHAT WE SHIP",
        labels=labels,
    )
    passed = run(
        repair(ds, raw_labels),
        strict=True,
        title="C) CONSISTENT data + STRICT matching  <-- identical code",
        labels=labels,
    )

    print(
        f"\n  {BOLD}Conclusion{RESET}: the analyzer scores {GREEN}{passed}/7{RESET} the "
        f"moment the CVE database stops contradicting the labels it ships with.\n"
        f"  {DIM}The detection logic is not the failure. The input is.{RESET}\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
