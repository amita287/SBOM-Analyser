"""Phase 8 — evaluation harness (Section 10).

Reads the analyzer's ``reports/analysis.json`` and the generator's ground-truth
``data/dependency_labels.csv`` — the one place ground truth may be read — and
prints a color-coded pass/fail scorecard for the five headline metrics.

Exit code is 0 only if every metric passes, so this doubles as a CI gate.
"""

from __future__ import annotations

import csv
import os
import sys
from dataclasses import dataclass
from pathlib import Path

from sbom_analyzer.config import get_settings
from sbom_analyzer.models.findings import AnalysisReport, RiskType

# --------------------------------------------------------------------------- #
# ANSI colour (enabled on Windows consoles too)
# --------------------------------------------------------------------------- #
if sys.platform == "win32":
    os.system("")  # turn on virtual-terminal processing for ANSI escapes
try:  # ensure the box-drawing / ± / ✓ glyphs never crash a legacy code page
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:  # pragma: no cover - stdout may not be reconfigurable
    pass

GREEN, RED, YELLOW = "\033[92m", "\033[91m", "\033[93m"
BOLD, DIM, CYAN, RESET = "\033[1m", "\033[2m", "\033[96m", "\033[0m"


# --------------------------------------------------------------------------- #
# Loading the two sides
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Record:
    risk_types: set[str]
    risk_score: float

    @property
    def is_risk(self) -> bool:
        return bool(self.risk_types - {"clean"})


def load_predictions(report_path: Path) -> tuple[dict[str, Record], str]:
    """Return the per-dependency predictions plus a provenance line."""
    report = AnalysisReport.model_validate_json(report_path.read_text(encoding="utf-8"))
    preds: dict[str, Record] = {}
    for app in report.apps:
        for f in app.findings:
            preds[f.dependency_id] = Record(
                risk_types={rt.value for rt in f.risk_types},
                risk_score=f.risk_score,
            )

    # Read provenance off the report, not the environment — the scorecard must
    # never claim a run was deterministic when an LLM actually touched it.
    if report.llm_provider == "none":
        provenance = "LLM disabled — fully deterministic pipeline"
    elif report.llm_affects_score:
        provenance = (
            f"LLM enabled ({report.llm_provider}) and FEEDING SCORES — "
            "these numbers are LLM-influenced"
        )
    else:
        provenance = (
            f"LLM enabled ({report.llm_provider}), advisory only — scores deterministic"
        )
    return preds, provenance


def load_labels(labels_path: Path) -> dict[str, Record]:
    labels: dict[str, Record] = {}
    with labels_path.open("r", encoding="utf-8", newline="") as fh:
        for row in csv.DictReader(fh):
            labels[row["dependency_id"]] = Record(
                risk_types={p for p in row["risk_types"].split("|") if p},
                risk_score=float(row["risk_score"]),
            )
    return labels


# --------------------------------------------------------------------------- #
# Metrics
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Metric:
    name: str
    value: float          # 0..1
    target_text: str
    passed: bool
    detail: str


def _recall(preds, labels, risk_type: str) -> tuple[float, int, int]:
    labeled = [d for d, r in labels.items() if risk_type in r.risk_types]
    hits = sum(
        1 for d in labeled if risk_type in preds.get(d, Record(set(), 0.0)).risk_types
    )
    total = len(labeled)
    return (hits / total if total else 1.0), hits, total


def compute_metrics(preds: dict[str, Record], labels: dict[str, Record]) -> list[Metric]:
    # 1. Vulnerability detection recall  (> 85%)
    v, vh, vt = _recall(preds, labels, "vulnerable")
    # 2. Transitive resolution           (= 100%)
    t, th, tt = _recall(preds, labels, "transitive_vulnerable")
    # 3. License conflict detection      (> 90%)
    lc, lh, lt = _recall(preds, labels, "license_conflict")

    # 4. False-positive rate             (< 20%)
    flagged = [d for d, r in preds.items() if r.is_risk]
    fps = sum(1 for d in flagged if not labels.get(d, Record(set(), 0.0)).is_risk)
    fp_rate = (fps / len(flagged)) if flagged else 0.0

    # 5. Risk score accuracy within +/-10%   (>= 90%)
    within = 0
    for d, truth in labels.items():
        pred = preds.get(d)
        if pred is None:
            continue
        tol = 0.10 * abs(truth.risk_score) + 1e-9
        if abs(pred.risk_score - truth.risk_score) <= tol:
            within += 1
    acc = within / len(labels) if labels else 1.0

    return [
        Metric("Vulnerability detection recall", v, "> 85%", v > 0.85, f"{vh}/{vt}"),
        Metric("Transitive resolution", t, "= 100%", t >= 1.0, f"{th}/{tt}"),
        Metric("License conflict detection", lc, "> 90%", lc > 0.90, f"{lh}/{lt}"),
        Metric("False positive rate", fp_rate, "< 20%", fp_rate < 0.20, f"{fps}/{len(flagged)}"),
        Metric("Risk score accuracy (±10%)", acc, "≥ 90%", acc >= 0.90, f"{within}/{len(labels)}"),
    ]


# --------------------------------------------------------------------------- #
# Scorecard rendering
# --------------------------------------------------------------------------- #
def print_scorecard(metrics: list[Metric], provenance: str) -> bool:
    name_w = max(len(m.name) for m in metrics)
    header = f"  {'METRIC':<{name_w}}   {'RESULT':>8}   {'TARGET':>7}   {'DETAIL':>9}   STATUS"
    line = "  " + "─" * (len(header) + 4)

    print()
    print(f"{BOLD}{CYAN}  SBOM Analyzer — Metric Scorecard{RESET}")
    print(line)
    print(f"{BOLD}{header}{RESET}")
    print(line)
    for m in metrics:
        colour = GREEN if m.passed else RED
        status = f"{colour}{'PASS' if m.passed else 'FAIL'}{RESET}"
        pct = f"{m.value * 100:.1f}%"
        print(
            f"  {m.name:<{name_w}}   {colour}{pct:>8}{RESET}   "
            f"{m.target_text:>7}   {DIM}{m.detail:>9}{RESET}   {status}"
        )
    print(line)

    all_pass = all(m.passed for m in metrics)
    if all_pass:
        print(f"{BOLD}{GREEN}  ✓ ALL METRICS PASS{RESET}")
    else:
        failed = ", ".join(m.name for m in metrics if not m.passed)
        print(f"{BOLD}{RED}  ✗ FAILED: {failed}{RESET}")
    print(f"{DIM}  run: {provenance}{RESET}")
    print()
    return all_pass


def main() -> int:
    settings = get_settings()
    report_path = settings.reports_dir / "analysis.json"
    labels_path = settings.data_dir / "dependency_labels.csv"

    if not report_path.is_file():
        print(f"{RED}No report at {report_path}. Run: python scripts/run_analysis.py{RESET}")
        return 2
    if not labels_path.is_file():
        print(f"{RED}No labels at {labels_path}. Run: python scripts/generate_sample_data.py{RESET}")
        return 2

    preds, provenance = load_predictions(report_path)
    labels = load_labels(labels_path)
    metrics = compute_metrics(preds, labels)
    all_pass = print_scorecard(metrics, provenance)
    return 0 if all_pass else 1


if __name__ == "__main__":
    raise SystemExit(main())
