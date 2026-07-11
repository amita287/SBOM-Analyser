"""FastAPI app + routers (Phase 7, Section 9.3).

Phase 0 skeleton: exposes only a ``/health`` probe so the app is runnable
(``uvicorn sbom_analyzer.api.main:app``). The analysis routes — POST /analyze,
GET /runs/{id}/report, GET /apps/{app_id}, GET /findings — arrive in Phase 7.
"""

from __future__ import annotations

from fastapi import FastAPI

from .. import __version__

app = FastAPI(title="SBOM Analyzer", version=__version__)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "version": __version__}
