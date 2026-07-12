# SBOM Analyzer — Project Handoff (backend complete → frontend work)

I'm picking up frontend development on an existing, working Python project. The
backend is finished and passing all its metrics. Below is the full context.

---

## 1. What this is

**SBOM Analyzer — Software Supply Chain Risk Scorer** (challenge PB-10).

It ingests a synthetic SBOM (10 applications, 500 dependency occurrences, 200
CVEs), builds a dependency graph, and scores supply-chain risk per dependency and
per app. Four risk types: `vulnerable`, `transitive_vulnerable`, `license_conflict`,
`unmaintained`.

**Architecture rule that governs everything:** a deterministic core (graph +
scoring), with the LLM used *only* for prose (narratives, remediation wording) and
bounded adjudications. **The LLM never produces a number that feeds a metric.** The
whole pipeline runs and passes with `LLM_PROVIDER=none`.

### Phases completed (0–8, all done)

| Phase | What |
| --- | --- |
| 0 | Scaffold + Pydantic data contracts |
| 1 | Deterministic synthetic-data generator (seed 42, frozen date `2026-04-15`) |
| 2 | Ingestion loaders — validate every row, fail loudly |
| 3 | NetworkX dependency graph (`DiGraph`) + traversal |
| 4 | Deterministic analysis: version-range CVE matching (`packaging.SpecifierSet`), license rule engine, staleness, transitive exposure |
| 5 | Risk scorer + golden unit tests |
| 6 | Four LLM reasoners (exploitability, false-positive, attack-chain narrative, remediation) — each with a deterministic fallback |
| 7 | Reporting: `analysis.json`, Jinja2 HTML report, FastAPI |
| 8 | Eval harness / scorecard |

### Current metrics (deterministic run, no LLM)

| Metric | Result | Target |
| --- | --- | --- |
| Vulnerability detection recall | 100% | > 85% |
| Transitive resolution | 100% | = 100% |
| License conflict detection | 100% | > 90% |
| False positive rate | 0% | < 20% |
| Risk score accuracy (±10%) | 100% | ≥ 90% |

`pytest` = 81 passing. `reports/analysis.json` is byte-identical across runs.

---

## 2. Folder structure

```
c:\SBOM-Analyser\
├── data/                              # inputs (generated, committed)
│   ├── applications.json              # 10 apps
│   ├── sbom_dependencies.csv          # 500 rows — HAS parent_dependency_id (graph edges)
│   ├── vulnerability_db.json          # 200 CVEs
│   ├── license_rules.json             # category + compatibility matrix
│   └── dependency_labels.csv          # GROUND TRUTH — eval harness ONLY, never read by the app
├── reports/
│   ├── analysis.json                  # canonical machine-readable output (~615 KB)
│   └── report.html                    # rendered human report (~697 KB, self-contained)
├── scripts/
│   ├── generate_sample_data.py
│   ├── run_analysis.py                # full pipeline → writes both reports/ artifacts
│   └── evaluate.py                    # prints the 5-metric scorecard
├── src/sbom_analyzer/
│   ├── config.py                      # settings from .env
│   ├── models/
│   │   ├── entities.py                # input contracts (Application, Dependency, Vulnerability, LicenseRules)
│   │   └── findings.py                # OUTPUT contracts — AnalysisReport, AppRiskReport, DependencyFinding
│   ├── ingestion/loaders.py
│   ├── graph/
│   │   ├── builder.py                 # build_graph(applications, dependencies) -> nx.DiGraph
│   │   └── traversal.py               # descendants_of, paths_to_vulnerable, is_on_path_to_vulnerable
│   ├── analysis/                      # vulnerabilities / licenses / maintenance / transitive
│   ├── scoring/risk.py                # THE risk formula — single source of truth
│   ├── llm/                           # client.py, prompts.py, reasoners.py
│   ├── reporting/
│   │   ├── report.py                  # build_report() -> AnalysisReport; write_report()
│   │   ├── html.py                    # render_html() / write_html()
│   │   └── templates/report.html.j2   # the existing HTML report
│   └── api/main.py                    # FastAPI app  ← frontend integrates here
├── tests/                             # 81 tests
├── pyproject.toml
├── .env / .env.example
├── CLAUDE.md                          # project rules (read this)
└── SBOM_Analyzer_Implementation_Plan.md   # full spec
```

---

## 3. FastAPI endpoints (`src/sbom_analyzer/api/main.py`)

Run: `uvicorn sbom_analyzer.api.main:app --reload` → `http://127.0.0.1:8000`
OpenAPI docs at `/docs`.

`{run_id}` accepts the literal string **`latest`** everywhere. Runs are held in
memory; the last `reports/analysis.json` on disk is adopted at startup, so all GETs
work immediately without POSTing first.

| Route | Returns |
| --- | --- |
| `GET /health` | `{"status": "ok", "version": "0.1.0"}` |
| `POST /analyze?persist=true` | **201** + `RunSummary` (below). Runs the pipeline; `persist=true` (default) rewrites `reports/analysis.json` + `report.html` |
| `GET /runs` | `[{run_id, generated_at, llm_provider}]` |
| `GET /runs/{run_id}` | `RunSummary` |
| `GET /runs/{run_id}/report` | **the full `AnalysisReport`** — identical to `analysis.json` |
| `GET /runs/{run_id}/report.html` | `text/html` — the rendered report |
| `GET /apps/{app_id}` | one `AppRiskReport` (findings ranked worst-first). 404 on unknown id |
| `GET /findings` | `DependencyFinding[]`, sorted by `risk_score` desc |

**`GET /findings` query params:**
- `risk_type` — `vulnerable` \| `transitive_vulnerable` \| `license_conflict` \| `unmaintained` \| `clean`
- `app_id` — restrict to one app
- `min_score` — float 0–100 (default 0)
- `limit` — 1–1000 (default **100** — raise it, there are 320 at-risk findings)
- `run_id` — default `latest`

> With **no** `risk_type`, `/findings` returns only *at-risk* findings (clean are
> excluded as noise). Ask for clean explicitly with `?risk_type=clean`.

**`RunSummary` shape:**
```json
{
  "run_id": "run-2026-04-15-001",
  "status": "complete",
  "generated_at": "2026-04-15T00:00:00",
  "llm_provider": "none",
  "llm_affects_score": false,
  "apps": 10,
  "findings": 500,
  "at_risk": 320,
  "totals_per_risk_type": {"vulnerable": 128, "transitive_vulnerable": 99,
                           "license_conflict": 60, "unmaintained": 102, "clean": 180},
  "llm_calls": 0,
  "llm_fallbacks": 0,
  "llm_last_error": null
}
```

---

## 4. Shape of `analysis.json` (= `GET /runs/latest/report`)

```jsonc
{
  "run_id": "run-2026-04-15",
  "generated_at": "2026-04-15T00:00:00",   // frozen date, not wall clock

  // provenance — how the run was produced
  "llm_provider": "none",        // "none" | "openai" | "anthropic"
  "llm_affects_score": false,    // false = scores are 100% deterministic
  "llm_calls": 0,
  "llm_fallbacks": 0,            // if llm_calls == llm_fallbacks, ALL prose is template-generated

  "apps": [ /* AppRiskReport[] — 10 */ ],

  "summary": {
    "totals_per_risk_type": {
      "vulnerable": 128, "transitive_vulnerable": 99,
      "license_conflict": 60, "unmaintained": 102, "clean": 180
    },
    "top_riskiest": [            // 10 items, global, ranked
      { "dependency_id": "DEP-00026", "app_id": "APP-001",
        "library_name": "vuln-lib-0027", "version": "2.5.1",
        "risk_score": 100.0, "severity": "critical" }
    ],
    "dedup_note": "35 vulnerable library/version pair(s) span multiple apps; widest blast radius: shiro 3.5.1 in 6 apps."
  }
}
```

**Totals sum to more than 500** — a dependency can carry several risk types
(e.g. `["vulnerable", "license_conflict"]`). 500 findings, 320 at-risk, 180 clean.

---

## 5. Field reference

### `AppRiskReport` (10 of them)
| Field | Type | Notes |
| --- | --- | --- |
| `app_id` | str | `"APP-001"` … `"APP-010"` |
| `name` | str | `"customer-portal"` |
| `business_criticality` | enum | `critical` \| `high` \| `medium` \| `low` |
| `app_score` | float | 0–100 |
| `severity` | enum | `critical` \| `high` \| `medium` \| `low` \| `none` |
| `findings` | `DependencyFinding[]` | ~50 per app, already ranked worst-first |

### `DependencyFinding` (500 total)
| Field | Type | Notes |
| --- | --- | --- |
| `dependency_id` | str | `"DEP-00026"` — **this is the graph node id** |
| `app_id` | str | owning app |
| `library_name` | str | |
| `version` | str | `"2.5.1"` |
| `ecosystem` | enum | `npm` \| `pypi` \| `maven` |
| `license` | str | SPDX id, `""` = unknown |
| `risk_score` | float | 0–100 |
| `severity` | enum | `critical` ≥75, `high` ≥50, `medium` ≥25, `low` >0, `none` =0 |
| `risk_types` | enum[] | any of `vulnerable`, `transitive_vulnerable`, `license_conflict`, `unmaintained`, or exactly `["clean"]` |
| `matched_cves` | `MatchedVulnerability[]` | see below |
| `license_outcome` | enum | `conflict` \| `review` \| `ok` |
| `maintenance` | object \| null | `{last_updated, age_years, is_stale, maintenance_penalty}` |
| `attack_paths` | `AttackPath[]` | present on the *vulnerable* dep (the path terminus) |
| `narrative` | str \| null | attack-chain prose; present on all 128 vulnerable findings |
| `remediation` | object \| null | `{steps: string[], priority: "P1"\|"P2"\|"P3"}` — present on all 320 at-risk |
| `llm_enriched` | bool | **true only if an LLM actually wrote the prose.** false = deterministic template. Don't credit the model in the UI unless this is true |

### `MatchedVulnerability`
```jsonc
{
  "cve_id": "CVE-2018-44027",
  "cvss_score": 7.9,
  "cvss_severity": "high",              // critical|high|medium|low
  "affected_versions": ">=2.0.0,<2.6.0",
  "patch_available": false,
  "fixed_version": null,                // null when no patch
  "vulnerable_function": "VulnLib0027.parseObject",
  "is_false_positive": false,           // true = version is a backported-safe build; render struck-through
  "exploitability": "imports_only",     // calls_vulnerable_function | imports_only | not_referenced
  "cve_score": 67.15                    // this CVE's contribution to the risk score
}
```

### `AttackPath`
```jsonc
{
  "app_id": "APP-001",
  "path": ["APP-001", "DEP-00004", "DEP-00025", "DEP-00026"],  // app node → … → vulnerable dep
  "vulnerable_dependency_id": "DEP-00026",
  "cve_id": "CVE-2018-44027",
  "narrative": "customer-portal reaches vuln-lib-0027 2.5.1 through … (2 hop(s))."
}
```
`path[0]` is an **app_id**; the rest are **dependency_ids**. Resolve ids → labels by
building a map from every finding (`dependency_id` → `library_name` + `version`) and
every app (`app_id` → `name`). 128 attack paths exist, up to 5 nodes long.

---

## 6. Frontend that already exists

**`reports/report.html`** — a Jinja2-rendered, fully self-contained static page
(no external CSS/JS/fonts; opens offline). Template:
`src/sbom_analyzer/reporting/templates/report.html.j2`, renderer:
`src/sbom_analyzer/reporting/html.py`.

It has: a masthead with run + LLM-provenance pills, a KPI strip, a top-10 table, a
blast-radius callout, and per-app collapsible sections (sorted by `app_score` desc)
where each at-risk finding expands to its CVE table, attack paths, narrative, and
remediation. Traffic-light colours: critical `#dc2626`, high `#ea580c`,
medium `#d97706`, low `#16a34a`, none `#94a3b8`.

It is a **static server-rendered report, not an app** — no JS, no interactivity
beyond `<details>` toggles, no dependency-graph visualisation. Treat it as the
visual reference / style guide, not something to extend.

---

## 7. What still needs to be built

### 7a. Cytoscape.js dependency-graph visualisation
Interactive graph: app → direct deps → transitive deps, nodes coloured by
severity, vulnerable nodes highlighted, attack paths traceable from app to CVE.

> **BLOCKER — there is no graph endpoint.** `analysis.json` contains
> `attack_paths` (edges *only* along the 128 paths that reach a vulnerable node),
> **not the full dependency graph**. The complete edge list lives in
> `data/sbom_dependencies.csv` (`parent_dependency_id` → child; empty parent means
> the app is the parent) and the backend already builds it with NetworkX in
> `src/sbom_analyzer/graph/builder.py`.
>
> **First task: add `GET /graph` (and/or `GET /apps/{app_id}/graph`)** to
> `api/main.py` that returns Cytoscape-ready elements, e.g.
> `{"nodes": [{"data": {"id", "label", "kind": "application"|"dependency", "severity", "risk_score", "risk_types"}}], "edges": [{"data": {"source", "target"}}]}`.
> Reuse `build_graph()` — do **not** re-parse the CSV in the frontend, and do not
> reconstruct the graph from attack paths (it would be missing most edges).

### 7b. Dashboard
Metrics/KPI overview, per-app drilldown, filterable findings table, top-risk list,
blast-radius view. All backed by the endpoints in §3.

### 7c. Known gaps to fix along the way
- **No CORS middleware.** A dev server on `http://localhost:5173` will be blocked
  by the browser. Add `CORSMiddleware` to `api/main.py` before doing anything else.
- `GET /findings` defaults to `limit=100`; there are 320 at-risk findings.
- Runs are **in-memory only** — a server restart forgets POSTed runs (it re-adopts
  `reports/analysis.json` at startup).

---

## 8. Tech stack

**Backend:** Python 3.13 (project declares `>=3.11` — **no PEP 695 generics**),
FastAPI + Uvicorn, Pydantic v2, NetworkX, `packaging` (version ranges), Jinja2,
httpx, python-dotenv, pytest. Optional: `anthropic` SDK (extra `[llm]`, lazily
imported).

**Frontend:** nothing chosen yet beyond the plan to use **Cytoscape.js**. No
`package.json`, no bundler, no framework in the repo — greenfield.

**LLM:** provider-agnostic client supporting Anthropic and any OpenAI-compatible
endpoint (`LLM_BASE_URL`, e.g. OpenRouter/Ollama). Currently `LLM_PROVIDER=none`;
the OpenRouter key in `.env` is out of credits, so LLM-enabled runs degrade to
deterministic fallbacks (correctly, and visibly).

---

## 9. Running it locally

```bash
cd c:\SBOM-Analyser
python -m venv .venv
.venv\Scripts\activate            # POSIX: source .venv/bin/activate
pip install -e .

# 1. (data is already committed; regenerate only if needed)
python scripts/generate_sample_data.py

# 2. run the pipeline → writes reports/analysis.json + reports/report.html
python scripts/run_analysis.py

# 3. verify the 5 metrics
python scripts/evaluate.py

# 4. tests
pytest                            # 81 passing

# 5. API for the frontend
uvicorn sbom_analyzer.api.main:app --reload
#    → http://127.0.0.1:8000/docs
#    → http://127.0.0.1:8000/runs/latest/report
```

`.env` (copy from `.env.example`): keep `LLM_PROVIDER=none` for frontend work —
it's fast, deterministic, offline, and produces the exact same report shape.

---

## 10. Project rules to respect (from `CLAUDE.md`)

- Never use an LLM to produce numbers that feed a metric (scores, severities, vuln matches).
- The dependency graph is built by parsing, **never** by an LLM.
- Version matching uses `packaging.specifiers.SpecifierSet`, never string comparison.
- Frozen date: `TODAY = date(2026, 4, 15)` — never `datetime.now()`. Seed 42.
- `data/dependency_labels.csv` is ground truth: **eval harness only**, never read by
  the analyzer or served by the API.
- `LLM_PROVIDER=none` must always produce passing metrics.
