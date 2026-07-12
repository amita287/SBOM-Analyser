# SBOM Analyzer — Software Supply Chain Risk Scorer

GRC Hackathon, **Problem 10**. Ingests an SBOM, cross-references a CVE database,
resolves transitive dependency chains, checks licence compatibility, flags
unmaintained libraries, and scores supply-chain risk per dependency and per
application.

**Architecture:** a deterministic core (graph + detection + scoring) with an LLM
used *only* for prose and bounded adjudications. **No model output ever produces a
number that feeds a metric** — that boundary is enforced by a config gate, not by
good intentions.

---

## Run it

```bash
git clone https://github.com/amita287/SBOM-Analyser.git
cd SBOM-Analyser

python -m venv .venv
.venv\Scripts\activate           # POSIX: source .venv/bin/activate
pip install -e .

python scripts/run_analysis.py   # -> reports/analysis.json + report.html
python scripts/evaluate.py       # the scorecard
pytest                           # 88 tests
```

### The console

```bash
uvicorn sbom_analyzer.api.main:app --reload
```

→ **http://127.0.0.1:8000** (redirects to the dashboard).

The API self-bootstraps: with no `reports/analysis.json` it analyses `data/` during
startup, so a fresh clone works with nothing but `uvicorn`.

| Page | |
|---|---|
| `/static/dashboard.html` | KPIs, risk mix, riskiest applications, top-10 findings |
| `/static/applications.html` | Sortable table — click a row for its full report |
| `/static/graph.html` | Interactive Cytoscape dependency graph, attack paths in red |
| `/static/findings.html` | Every finding, filterable, expandable |
| `/static/upload.html` | Drop in your own `sbom_dependencies.csv` |
| `/docs` | OpenAPI |

Light and dark themes (sidebar toggle). `/` or `⌘K` opens a search across
applications, libraries, dependency ids and CVE ids.

### Optional — enable the LLM

Copy `.env.example` to `.env`:

```ini
LLM_PROVIDER=gemini              # none | openai | anthropic | gemini
LLM_API_KEY=your-key
LLM_MODEL=gemini-flash-lite-latest
LLM_AFFECTS_SCORE=false          # keep this false — see below
```

With `LLM_PROVIDER=none` the pipeline is fully deterministic and every section of
the report is still populated, by template fallbacks. The LLM writes attack-chain
narratives and remediation playbooks and adjudicates ambiguous CVE matches, but
`LLM_AFFECTS_SCORE=false` keeps its verdicts advisory. `.env` is gitignored.

#Layout
```
data/            the 6 supplied files. dependency_labels.csv is GROUND TRUTH and is
                 read ONLY by scripts/evaluate.py — never by the analyzer
src/sbom_analyzer/
  ingestion/     validating loaders (a bad row fails loudly, never silently)
  graph/         NetworkX DiGraph: app -> dependency -> transitive child
  analysis/      CVE matching, licence rules, staleness, risk classification
  scoring/       the risk formula — single source of truth, no LLM
  llm/           provider-agnostic client + reasoners, each with a deterministic fallback
  reporting/     analysis.json, the HTML report
  api/           FastAPI + the console
  static/        the console (no build step, no framework)
scripts/         run_analysis · evaluate · data_integrity · engine_check
```

---

## Deploy

Any host that runs a container. The image analyses `data/` on boot, so there is no
build step to forget.

```bash
docker build -t sbom-analyzer .
docker run -p 8000:8000 sbom-analyzer
```

**Render / Railway / Fly.io** — point them at this repo. The `Dockerfile` is picked
up automatically and `$PORT` is honoured. Leave `LLM_PROVIDER=none` (the default)
unless you add a key as a secret.

Without Docker:

```bash
pip install -e .
uvicorn sbom_analyzer.api.main:app --host 0.0.0.0 --port $PORT
```

