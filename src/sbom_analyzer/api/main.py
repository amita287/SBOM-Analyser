"""FastAPI app (Phase 7, Section 9.3).

    uvicorn sbom_analyzer.api.main:app --reload

Endpoints
---------
- ``POST /analyze``            trigger a run over ``data/``; returns a run id
- ``GET  /runs``               list known runs
- ``GET  /runs/{id}``          run status + headline counts
- ``GET  /runs/{id}/report``   the full JSON report
- ``GET  /runs/{id}/report.html``  the rendered HTML report
- ``GET  /apps/{app_id}``      one app's findings, ranked
- ``GET  /findings``           findings filtered by risk type / app / score

``{id}`` accepts the literal ``latest`` everywhere a run id is taken.

Runs are held in memory (a process restart forgets them) and the most recent
``reports/analysis.json`` on disk is adopted at startup, so every GET works
immediately after a CLI run without POSTing first. A durable run store is out of
scope for this challenge; the CLI remains the source of truth for artifacts.

Analysis is synchronous: the dataset is small and, with the LLM off, a run takes
milliseconds. The route handlers are declared ``def`` (not ``async def``) so
FastAPI executes them in a worker thread — a slow LLM-enabled run cannot block
the event loop.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import asynccontextmanager, suppress
from datetime import datetime
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .. import __version__
from ..analysis.maintenance import TODAY
from ..config import get_settings
from ..graph.builder import NODE_KIND_APP, NODE_KIND_DEP, build_graph
from ..ingestion.loaders import DataValidationError, load_dataset
from ..llm.client import LLMClient
from ..models.entities import Application
from ..models.findings import (
    AnalysisReport,
    AppRiskReport,
    DependencyFinding,
    RiskType,
)
from ..reporting.html import render_html, write_html
from ..reporting.report import build_report, write_report

LATEST = "latest"

# The static console (dashboard + graph) ships next to the package so it is
# installed with it and served from the same origin as the API.
STATIC_DIR = Path(__file__).resolve().parent.parent / "static"


# --------------------------------------------------------------------------- #
# Response models
# --------------------------------------------------------------------------- #
class RunSummary(BaseModel):
    """What a client gets back from POST /analyze and GET /runs/{id}."""

    run_id: str
    status: str = "complete"  # runs are synchronous; always terminal on return
    generated_at: datetime
    llm_provider: str
    llm_affects_score: bool
    apps: int
    findings: int
    at_risk: int
    totals_per_risk_type: dict[RiskType, int] = Field(default_factory=dict)
    # How often the LLM actually contributed vs. fell back (0/0 when disabled).
    # A silent degradation to deterministic output must never be invisible.
    llm_calls: int = 0
    llm_fallbacks: int = 0
    llm_last_error: str | None = None


class RunRef(BaseModel):
    run_id: str
    generated_at: datetime
    llm_provider: str


# --------------------------------------------------------------------------- #
# In-memory run store
# --------------------------------------------------------------------------- #
class RunStore:
    def __init__(self) -> None:
        self._runs: dict[str, AnalysisReport] = {}
        self._order: list[str] = []  # insertion order; last == latest

    def add(self, report: AnalysisReport) -> str:
        run_id = report.run_id
        if run_id not in self._runs:
            self._order.append(run_id)
        self._runs[run_id] = report
        return run_id

    def get(self, run_id: str) -> AnalysisReport | None:
        if run_id == LATEST:
            return self._runs[self._order[-1]] if self._order else None
        return self._runs.get(run_id)

    def list(self) -> list[AnalysisReport]:
        return [self._runs[r] for r in self._order]

    def next_run_id(self) -> str:
        """Stable, collision-free id — no wall clock (the date is frozen)."""
        return f"run-{TODAY.isoformat()}-{len(self._order) + 1:03d}"


store = RunStore()


@asynccontextmanager
async def lifespan(app: FastAPI):  # pragma: no cover - exercised via TestClient
    """Adopt the last CLI-written report so GETs work before any POST."""
    path = get_settings().reports_dir / "analysis.json"
    if path.is_file():
        with suppress(Exception):  # a stale/corrupt artifact must not block boot
            store.add(
                AnalysisReport.model_validate_json(path.read_text(encoding="utf-8"))
            )
    yield


app = FastAPI(
    title="SBOM Analyzer",
    version=__version__,
    summary="Software supply chain risk scorer — deterministic core, LLM narratives.",
    lifespan=lifespan,
)

# The bundled console is same-origin, but a Vite/live-server dev loop on another
# port is not. Read-only API over a local, synthetic dataset — nothing to guard.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def _require_run(run_id: str) -> AnalysisReport:
    report = store.get(run_id)
    if report is None:
        if run_id == LATEST and not store.list():
            raise HTTPException(
                status_code=404,
                detail="No analysis run available. POST /analyze first.",
            )
        raise HTTPException(status_code=404, detail=f"Unknown run id: {run_id!r}")
    return report


def _summarize(report: AnalysisReport, client: LLMClient | None = None) -> RunSummary:
    """Counts come off the report, so a GET is as truthful as the original POST."""
    findings = [f for app in report.apps for f in app.findings]
    return RunSummary(
        run_id=report.run_id,
        generated_at=report.generated_at,
        llm_provider=report.llm_provider,
        llm_affects_score=report.llm_affects_score,
        apps=len(report.apps),
        findings=len(findings),
        at_risk=sum(1 for f in findings if f.is_risk),
        totals_per_risk_type=report.summary.totals_per_risk_type,
        llm_calls=report.llm_calls,
        llm_fallbacks=report.llm_fallbacks,
        # Only the live client knows *why* a call failed; a rehydrated run doesn't.
        llm_last_error=client.last_error if client is not None else None,
    )


def _all_findings(report: AnalysisReport) -> Iterator[DependencyFinding]:
    for app in report.apps:
        yield from app.findings


# --------------------------------------------------------------------------- #
# Routes
# --------------------------------------------------------------------------- #
@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "version": __version__}


@app.post("/analyze", response_model=RunSummary, status_code=201)
def analyze(
    persist: bool = Query(
        True,
        description="Also write reports/analysis.json and reports/report.html, "
        "overwriting the previous artifacts.",
    ),
) -> RunSummary:
    """Run the full pipeline over the files in ``data/`` and register the run.

    Honours the process settings, so ``LLM_PROVIDER=none`` gives the pure
    deterministic report here exactly as it does on the CLI.
    """
    settings = get_settings()
    try:
        dataset = load_dataset(settings.data_dir)
    except (DataValidationError, FileNotFoundError) as exc:
        # Bad input data is the caller's problem, not a server fault.
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    client = LLMClient(settings)
    report = build_report(
        dataset,
        run_id=store.next_run_id(),
        client=client,
        settings=settings,
    )
    store.add(report)

    if persist:
        write_report(report, settings.reports_dir / "analysis.json")
        write_html(report, settings.reports_dir / "report.html")

    return _summarize(report, client)


@app.get("/runs", response_model=list[RunRef])
def list_runs() -> list[RunRef]:
    return [
        RunRef(
            run_id=r.run_id,
            generated_at=r.generated_at,
            llm_provider=r.llm_provider,
        )
        for r in store.list()
    ]


@app.get("/runs/{run_id}", response_model=RunSummary)
def get_run(run_id: str) -> RunSummary:
    return _summarize(_require_run(run_id))


@app.get("/runs/{run_id}/report", response_model=AnalysisReport)
def get_report(run_id: str) -> AnalysisReport:
    """The full JSON report — identical to ``reports/analysis.json``."""
    return _require_run(run_id)


@app.get("/runs/{run_id}/report.html", response_class=HTMLResponse)
def get_report_html(run_id: str) -> HTMLResponse:
    return HTMLResponse(render_html(_require_run(run_id)))


@app.get("/apps/{app_id}", response_model=AppRiskReport)
def get_app(app_id: str, run_id: str = LATEST) -> AppRiskReport:
    """One application's findings, ranked worst-first."""
    report = _require_run(run_id)
    for app in report.apps:
        if app.app_id == app_id:
            return app
    raise HTTPException(status_code=404, detail=f"Unknown app id: {app_id!r}")


@app.get("/applications", response_model=list[Application])
def list_applications() -> list[Application]:
    """The application records as they were ingested.

    `AppRiskReport` carries the *scored* view of an app — it deliberately drops
    the descriptive fields (owner, environment, internet_facing) because scoring
    has no use for them. The console does: an app's owner is who you actually
    send the P1 to. Ten tiny records, straight off the loader.
    """
    try:
        return load_dataset(get_settings().data_dir).applications
    except (DataValidationError, FileNotFoundError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.get("/findings", response_model=list[DependencyFinding])
def get_findings(
    risk_type: RiskType | None = Query(
        None, description="Filter to one risk type, e.g. `vulnerable`."
    ),
    app_id: str | None = Query(None, description="Restrict to one application."),
    min_score: float = Query(0.0, ge=0.0, le=100.0),
    limit: int = Query(100, ge=1, le=1000),
    run_id: str = LATEST,
) -> list[DependencyFinding]:
    """Findings across all apps, filtered and ranked by risk score.

    With no ``risk_type`` this returns only *at-risk* findings — the clean 300-odd
    are noise for a query endpoint. Ask for them explicitly with
    ``?risk_type=clean``.
    """
    report = _require_run(run_id)
    results = [
        f
        for f in _all_findings(report)
        if (risk_type in f.risk_types if risk_type is not None else f.is_risk)
        and (app_id is None or f.app_id == app_id)
        and f.risk_score >= min_score
    ]
    results.sort(key=lambda f: (-f.risk_score, f.dependency_id))
    return results[:limit]


# --------------------------------------------------------------------------- #
# Graph — the dependency DAG, in Cytoscape's element shape
#
# The report carries `attack_paths`, but those only cover edges that terminate at
# a vulnerable node. Reconstructing the graph from them would silently drop most
# of the DAG, so this route goes back to the real edge list and reuses the very
# same `build_graph()` the analyzer runs on. Parsed, never inferred.
# --------------------------------------------------------------------------- #
class GraphNode(BaseModel):
    data: dict[str, object]


class GraphEdge(BaseModel):
    data: dict[str, object]


class GraphResponse(BaseModel):
    run_id: str
    nodes: list[GraphNode] = Field(default_factory=list)
    edges: list[GraphEdge] = Field(default_factory=list)


@app.get("/graph", response_model=GraphResponse)
def get_graph(
    app_id: str | None = Query(
        None,
        description="Restrict to one application's subtree. Omit for the whole estate "
        "(510 nodes — heavy to lay out; the console defaults to one app).",
    ),
    run_id: str = LATEST,
) -> GraphResponse:
    """The dependency DAG as Cytoscape elements, enriched with scored findings.

    Structure comes from the parsed SBOM; severity/score come from the run. The
    two are joined on ``dependency_id``, which is the graph node key on both sides.
    """
    report = _require_run(run_id)
    settings = get_settings()
    try:
        dataset = load_dataset(settings.data_dir)
        graph = build_graph(dataset.applications, dataset.dependencies)
    except (DataValidationError, FileNotFoundError, ValueError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    apps_by_id = {a.app_id: a for a in report.apps}
    if app_id is not None and app_id not in apps_by_id:
        raise HTTPException(status_code=404, detail=f"Unknown app id: {app_id!r}")

    findings = {f.dependency_id: f for f in _all_findings(report)}

    def in_scope(node_id: str, attrs: dict) -> bool:
        if app_id is None:
            return True
        if attrs.get("kind") == NODE_KIND_APP:
            return node_id == app_id
        return attrs.get("app_id") == app_id

    nodes: list[GraphNode] = []
    for node_id, attrs in graph.nodes(data=True):
        if not in_scope(node_id, attrs):
            continue

        if attrs.get("kind") == NODE_KIND_APP:
            owner = apps_by_id.get(node_id)
            nodes.append(
                GraphNode(
                    data={
                        "id": node_id,
                        "label": attrs.get("name", node_id),
                        "kind": NODE_KIND_APP,
                        "app_id": node_id,
                        "severity": owner.severity.value if owner else "none",
                        "risk_score": owner.app_score if owner else 0.0,
                        "risk_types": [],
                        "business_criticality": attrs.get("business_criticality"),
                        "internet_facing": attrs.get("internet_facing", False),
                        "distributed": attrs.get("distributed", False),
                    }
                )
            )
            continue

        # A dependency the analyzer never scored would be a real inconsistency;
        # surface it as `none` rather than dropping the node and hiding the hole.
        found = findings.get(node_id)
        nodes.append(
            GraphNode(
                data={
                    "id": node_id,
                    "label": attrs.get("library_name", node_id),
                    "kind": NODE_KIND_DEP,
                    "app_id": attrs.get("app_id"),
                    "version": attrs.get("version", ""),
                    "ecosystem": attrs.get("ecosystem"),
                    "license": attrs.get("license", ""),
                    "dependency_type": attrs.get("dependency_type"),
                    "severity": found.severity.value if found else "none",
                    "risk_score": found.risk_score if found else 0.0,
                    "risk_types": [rt.value for rt in found.risk_types]
                    if found
                    else [],
                    # Confirmed CVEs only. A dependency whose sole match is a
                    # backported-safe build is NOT carrying a live CVE, and the
                    # graph must not ring it in red — that is the exact false
                    # alarm the FP check exists to suppress. The dismissed ones
                    # are still counted, separately, so the UI can show its work.
                    "cve_count": sum(
                        1 for c in found.matched_cves if not c.is_false_positive
                    )
                    if found
                    else 0,
                    "dismissed_cve_count": sum(
                        1 for c in found.matched_cves if c.is_false_positive
                    )
                    if found
                    else 0,
                    "scored": found is not None,
                }
            )
        )

    node_ids = {n.data["id"] for n in nodes}
    edges = [
        GraphEdge(data={"id": f"{src}~{dst}", "source": src, "target": dst})
        for src, dst in graph.edges()
        if src in node_ids and dst in node_ids
    ]
    return GraphResponse(run_id=report.run_id, nodes=nodes, edges=edges)


# --------------------------------------------------------------------------- #
# Static console
# --------------------------------------------------------------------------- #
@app.get("/", include_in_schema=False)
def index() -> RedirectResponse:
    return RedirectResponse(url="/static/dashboard.html")


# check_dir=False: a missing console should 404 those paths, not refuse to boot
# the API it is only a client of.
app.mount(
    "/static",
    StaticFiles(directory=STATIC_DIR, html=True, check_dir=False),
    name="static",
)
