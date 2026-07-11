# CLAUDE.md

## Project
SBOM Analyzer — Software Supply Chain Risk Scorer

## Key Rules
- NEVER use LLM to produce numbers that feed a metric (scores, severities, vuln matches)
- Dependency graph built by parsing, NEVER by LLM
- Version matching uses packaging.specifiers.SpecifierSet, NEVER string comparison
- All LLM calls: temperature=0, JSON mode, Pydantic validated, with deterministic fallback
- Frozen date: TODAY = date(2026, 4, 15) — never use datetime.now()
- Random seed: SEED = 42

## Commands
- Generate data: `python scripts/generate_sample_data.py`
- Run analysis: `python scripts/run_analysis.py`  
- Evaluate: `python scripts/evaluate.py`
- Tests: `pytest`

## Architecture
- Generator and analyzer share ONLY scoring/risk.py — never detection logic
- LLM_PROVIDER=none must produce passing metrics (LLM is enhancement only)