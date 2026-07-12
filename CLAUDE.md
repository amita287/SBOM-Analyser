# CLAUDE.md

## Project
SBOM Analyzer — Software Supply Chain Risk Scorer (GRC Hackathon, Problem 10)

## Data
`data/` holds the **official hackathon dataset** — 6 files, supplied, never generated:
`applications.json`, `sbom_dependencies.csv`, `vulnerability_db.json`,
`license_rules.json`, `transitive_dependencies.json`, `dependency_labels.csv`.

- **`dependency_labels.csv` is THE ground truth.** It is read by `scripts/evaluate.py`
  and `scripts/data_integrity.py` and by nothing else, ever. If the analyzer reads it,
  the detection metrics become a tautology and the project is worthless.
- There is **no data generator**. Do not add one, and do not write a second ground-truth
  file — a self-generated "truth" that drifts from the supplied labels is worse than none.

## Key Rules
- NEVER use an LLM to produce a number that feeds a metric (scores, severities, vuln
  matches). Reasoner B *can* dismiss a CVE, so it is gated behind `LLM_AFFECTS_SCORE`
  (default false) and its verdict is otherwise advisory only.
- Dependency graph is built by parsing, NEVER by an LLM.
- Version matching is **exact membership** in `affected_versions` — that field is a
  discrete set, not a range (some advisories list versions descending). Never order or
  string-compare versions.
- All LLM calls: temperature=0, JSON mode, Pydantic-validated, with a deterministic
  fallback. The fallback KEEPS a finding; it never silently drops one.
- Frozen date: `TODAY = date(2026, 4, 15)` — never `datetime.now()`.
- `LLM_PROVIDER=none` must produce a complete report and reproducible metrics.

## Commands
- Run analysis: `python scripts/run_analysis.py`
- Evaluate: `python scripts/evaluate.py`
- Tests: `pytest`

## Known: the dataset contradicts itself
Not one of the 500 dependency versions appears in its own library's `affected_versions`,
yet the labels mark 176 vulnerable — so CVE matching falls back to the library name and
over-flags by construction. Two metrics (false-positive rate, severity agreement) are
therefore unreachable; `scripts/data_integrity.py` proves this on every run and the
scorecard marks them CAPPED rather than faking a pass. Do not "fix" them by reading the
labels into the analyzer.
