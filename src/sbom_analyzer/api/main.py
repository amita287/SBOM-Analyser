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
import csv
import io
import json
import tempfile
from contextlib import asynccontextmanager, suppress
from datetime import datetime
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, Query, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .. import __version__
from ..analysis.maintenance import TODAY
from ..config import get_settings
from ..analysis.vulnerabilities import VulnerabilityMatcher
from ..graph.builder import (
    NODE_KIND_APP,
    NODE_KIND_DEP,
    NODE_KIND_EXT,
    external_node_id,
)
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
    """Make sure a run exists before the first request.

    Adopt the last CLI-written report if there is one. If there ISN'T — a fresh
    clone, or a container whose `reports/` is empty — analyse `data/` right here.

    Without this, `uvicorn` starts happily and then answers every single endpoint
    with "No analysis run available. POST /analyze first." A deployed app that
    boots into a 404 and expects the visitor to know to POST something is broken,
    however correct each individual part of it is.
    """
    settings = get_settings()
    path = settings.reports_dir / "analysis.json"

    if path.is_file():
        with suppress(Exception):  # a stale/corrupt artifact must not block boot
            store.add(
                AnalysisReport.model_validate_json(path.read_text(encoding="utf-8"))
            )

    if not store.list():
        with suppress(Exception):  # no data/ dir? still boot; /health must answer
            report = build_report(
                load_dataset(settings.data_dir),
                run_id=store.next_run_id(),
                client=LLMClient(settings),
                settings=settings,
            )
            store.add(report)
            write_report(report, path)
            write_html(report, settings.reports_dir / "report.html")

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


def _synthesise_applications(staged: Path) -> None:
    """Derive `applications.json` from an uploaded SBOM's own columns.

    The CSV already names every application it references (`application_id`,
    `application_name`). The rest of the record — criticality, licence model,
    owner — is not in an SBOM and cannot be invented, so it takes an explicit,
    conservative default rather than a flattering one:

    - ``criticality: MEDIUM``      — neither alarmist nor dismissive.
    - ``license_model: proprietary`` — the setting under which a viral licence IS
      a conflict. Guessing "internal-only" would silently suppress every GPL
      finding in the upload, which is the one mistake here with legal consequences.

    Upload a real `applications.json` to score against your actual estate.
    """
    rows = csv.DictReader(
        io.StringIO(
            staged.joinpath("sbom_dependencies.csv").read_text(
                encoding="utf-8", errors="replace"
            ),
            newline="",
        )
    )

    seen: dict[str, str] = {}
    for row in rows:
        app_id = (row.get("application_id") or "").strip()
        if app_id and app_id not in seen:
            seen[app_id] = (row.get("application_name") or app_id).strip() or app_id

    staged.joinpath("applications.json").write_text(
        json.dumps(
            [
                {
                    "app_id": app_id,
                    "name": name,
                    "language": "",
                    "criticality": "MEDIUM",
                    "license_model": "proprietary",
                    "business_owner": "",
                    "department": "",
                    "deployment": "cloud",
                }
                for app_id, name in seen.items()
            ],
            indent=2,
        ),
        encoding="utf-8",
    )


@app.post("/analyze/upload", response_model=RunSummary, status_code=201)
def analyze_upload(
    sbom: UploadFile = File(..., description="sbom_dependencies.csv"),
    applications: UploadFile | None = File(None, description="applications.json"),
    vulnerability_db: UploadFile | None = File(None),
    license_rules: UploadFile | None = File(None),
    transitive_dependencies: UploadFile | None = File(None),
) -> RunSummary:
    """Analyse an uploaded SBOM.

    Only the dependency CSV is required. Anything not supplied falls back to the
    copy in ``data/`` — you rarely bring your own CVE feed or licence matrix, and
    demanding all five files just to look at one SBOM would make the feature
    useless.

    The upload is analysed in a temp directory and **never** writes to ``data/``.
    Someone dropping a file into a web form must not be able to overwrite the
    dataset the scorecard is measured against.

    The run is registered in memory and becomes ``latest``, so the whole console
    switches to it. Nothing is persisted to ``reports/``: a restart returns you to
    the canonical run, which is the right default for an ad-hoc upload.
    """
    settings = get_settings()

    # What may fall back to `data/`, and what may NOT.
    #
    # The CVE feed and the licence matrix are *reference* data — nobody brings
    # their own NVD to look at one SBOM, so those fall back.
    #
    # `transitive_dependencies.json` must NEVER fall back. Its edges belong to the
    # SBOM that was uploaded, and pairing 372 edges from the shipped dataset with
    # an uploaded CSV that declares none is a contradiction the loader rightly
    # rejects. The same edges already ride along on the CSV's `transitive_deps`
    # column, so nothing is lost by omitting the file.
    REFERENCE = {
        "vulnerability_db.json": vulnerability_db,
        "license_rules.json": license_rules,
    }

    with tempfile.TemporaryDirectory(prefix="sbom-upload-") as tmp:
        staged = Path(tmp)
        staged.joinpath("sbom_dependencies.csv").write_bytes(sbom.file.read())

        for name, upload in REFERENCE.items():
            if upload is not None and upload.filename:
                staged.joinpath(name).write_bytes(upload.file.read())
            elif (fallback := settings.data_dir / name).is_file():
                staged.joinpath(name).write_bytes(fallback.read_bytes())

        if transitive_dependencies is not None and transitive_dependencies.filename:
            staged.joinpath("transitive_dependencies.json").write_bytes(
                transitive_dependencies.file.read()
            )

        if applications is not None and applications.filename:
            staged.joinpath("applications.json").write_bytes(applications.file.read())
        else:
            # Synthesise the application inventory from the SBOM itself. Requiring
            # applications.json just to scan a dependency list would make the
            # feature useless for the common case: someone with one CSV.
            _synthesise_applications(staged)

        try:
            dataset = load_dataset(staged)
        except (DataValidationError, FileNotFoundError, ValueError) as exc:
            # A malformed upload is the caller's problem — and they need to be told
            # WHICH row and WHICH column. A bare "422" helps nobody.
            raise HTTPException(status_code=422, detail=str(exc)) from exc

        client = LLMClient(settings)
        report = build_report(
            dataset,
            run_id=f"upload-{store.next_run_id()}",
            client=client,
            settings=settings,
        )

    store.add(report)
    return _summarize(report, client)


@app.get(
    "/applications",
    response_model=list[Application],
    # `Application` declares validation aliases so it can read the dataset's own
    # column names (`business_owner`, `criticality`, `deployment`). FastAPI
    # serialises BY ALIAS by default, which would send those raw column names
    # straight back out — and the console, the report and every other consumer
    # speak the codebase's vocabulary, not the CSV's. Translate on the way in
    # only; the wire format stays consistent with the rest of the API.
    response_model_by_alias=False,
)
def list_applications() -> list[Application]:
    """The application records as they were ingested.

    `AppRiskReport` carries the *scored* view of an app — it deliberately drops
    the descriptive fields (owner, environment, license_model) because scoring
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
    """The dependency DAG as Cytoscape elements.

    Built from the RUN, not from `data/` on disk. That distinction is the whole
    bug it fixes: an uploaded SBOM becomes `latest`, but re-parsing `data/` served
    the shipped dataset's graph against the upload's findings, the app ids did not
    intersect, and the canvas rendered zero nodes.

    Everything needed is already on the report — `app_id` implies the app->dep
    edge, and `transitive_children` carries the dep->external ones — so the graph
    is a projection of the report rather than a second, divergent source of truth.
    """
    report = _require_run(run_id)

    apps_by_id = {a.app_id: a for a in report.apps}
    if app_id is not None and app_id not in apps_by_id:
        raise HTTPException(status_code=404, detail=f"Unknown app id: {app_id!r}")

    scoped = [a for a in report.apps if app_id is None or a.app_id == app_id]

    nodes: list[GraphNode] = []
    edges: list[GraphEdge] = []
    seen_ext: set[str] = set()

    for app in scoped:
        nodes.append(
            GraphNode(
                data={
                    "id": app.app_id,
                    "label": app.name,
                    "kind": NODE_KIND_APP,
                    "app_id": app.app_id,
                    "severity": app.severity.value,
                    "risk_score": app.app_score,
                    "risk_types": [],
                    "business_criticality": app.business_criticality.value,
                    "owner": app.owner,
                    "environment": app.environment,
                    "license_model": app.license_model,
                }
            )
        )

        for f in app.findings:
            nodes.append(
                GraphNode(
                    data={
                        "id": f.dependency_id,
                        "label": f.library_name,
                        "kind": NODE_KIND_DEP,
                        "app_id": f.app_id,
                        "version": f.version,
                        "license": f.license,
                        "dependency_type": f.dependency_type.value,
                        "severity": f.severity.value,
                        "risk_score": f.risk_score,
                        "risk_types": [rt.value for rt in f.risk_types],
                        "vuln_status": f.vuln_status.value,
                        # Confirmed CVEs only. A `potential` match — right library,
                        # wrong version — must NOT ring the node red: asserting a
                        # vulnerability the advisory never claimed is the exact
                        # false alarm the confidence tier exists to prevent.
                        "cve_count": len(f.confirmed_cves),
                        "unconfirmed_cve_count": len(f.potential_cves),
                        "scored": True,
                    }
                )
            )
            edges.append(
                GraphEdge(
                    data={
                        "id": f"{f.app_id}~{f.dependency_id}",
                        "source": f.app_id,
                        "target": f.dependency_id,
                    }
                )
            )

            # Phantom transitive children: named by the SBOM, never an SBOM row,
            # so never scored — but real structure, and a vulnerable one is a real
            # exposure. Drawn, flagged, and clearly marked unscored.
            for child in f.transitive_children:
                ext_id = external_node_id(f.app_id, child.library_name, child.version)
                if ext_id not in seen_ext:
                    seen_ext.add(ext_id)
                    nodes.append(
                        GraphNode(
                            data={
                                "id": ext_id,
                                "label": child.library_name,
                                "kind": NODE_KIND_EXT,
                                "app_id": f.app_id,
                                "version": child.version,
                                "severity": "none",
                                "risk_score": 0.0,
                                "risk_types": [],
                                "cve_count": len(child.cve_ids),
                                "scored": False,
                            }
                        )
                    )
                edges.append(
                    GraphEdge(
                        data={
                            "id": f"{f.dependency_id}~{ext_id}",
                            "source": f.dependency_id,
                            "target": ext_id,
                        }
                    )
                )

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
