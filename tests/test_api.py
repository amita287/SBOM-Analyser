"""Phase 7 — the API surface (Section 9.3).

Runs against the real dataset in ``data/`` through the real pipeline; the LLM is
forced off so these stay hermetic and fast.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from sbom_analyzer.api import main as api
from sbom_analyzer.config import LLMProvider, load_settings
from sbom_analyzer.models.findings import RiskType


@pytest.fixture
def client(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> TestClient:
    # Real data/, but a throwaway reports/ — POST /analyze persists by default and
    # must not overwrite the repo's artifacts during a test run. LLM forced off so
    # these stay hermetic (no network) whatever `.env` says.
    settings = load_settings().model_copy(
        update={"llm_provider": LLMProvider.none, "reports_dir": tmp_path}
    )
    monkeypatch.setattr(api, "get_settings", lambda: settings)
    monkeypatch.setattr(api, "store", api.RunStore())  # no cross-test leakage
    with TestClient(api.app) as c:
        yield c


@pytest.fixture
def analyzed(client: TestClient) -> TestClient:
    assert client.post("/analyze").status_code == 201
    return client


def test_health(client: TestClient) -> None:
    assert client.get("/health").json()["status"] == "ok"


def test_analyze_returns_a_run_id_and_headline_counts(client: TestClient) -> None:
    body = client.post("/analyze", params={"persist": False}).json()

    assert body["run_id"].startswith("run-2026-04-15-")
    assert body["status"] == "complete"
    assert body["apps"] == 10
    assert body["findings"] == 500
    assert 0 < body["at_risk"] < 500
    assert body["totals_per_risk_type"]["vulnerable"] > 0


def test_report_round_trips_through_the_run_store(analyzed: TestClient) -> None:
    run_id = analyzed.get("/runs").json()[-1]["run_id"]

    by_id = analyzed.get(f"/runs/{run_id}/report").json()
    by_latest = analyzed.get("/runs/latest/report").json()

    assert by_id == by_latest
    assert by_id["run_id"] == run_id
    assert len(by_id["apps"]) == 10


def test_report_html_is_served(analyzed: TestClient) -> None:
    resp = analyzed.get("/runs/latest/report.html")

    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/html")
    assert "Software Supply Chain Risk Report" in resp.text


def test_get_app_returns_findings_ranked_worst_first(analyzed: TestClient) -> None:
    app = analyzed.get("/apps/APP-001").json()

    assert app["app_id"] == "APP-001"
    scores = [f["risk_score"] for f in app["findings"]]
    assert scores == sorted(scores, reverse=True)


def test_findings_filter_by_risk_type(analyzed: TestClient) -> None:
    findings = analyzed.get(
        "/findings", params={"risk_type": "vulnerable", "limit": 1000}
    ).json()

    assert findings
    assert all(RiskType.vulnerable in f["risk_types"] for f in findings)


def test_findings_default_excludes_clean_and_respects_filters(analyzed: TestClient) -> None:
    default = analyzed.get("/findings", params={"limit": 1000}).json()
    assert all(f["risk_types"] != ["clean"] for f in default)

    scoped = analyzed.get(
        "/findings", params={"app_id": "APP-003", "min_score": 50.0, "limit": 1000}
    ).json()
    assert all(f["app_id"] == "APP-003" and f["risk_score"] >= 50.0 for f in scoped)

    # Clean findings are reachable, just not by default.
    clean = analyzed.get("/findings", params={"risk_type": "clean", "limit": 5}).json()
    assert clean and all(f["risk_types"] == ["clean"] for f in clean)


def test_unknown_ids_are_404_not_500(analyzed: TestClient) -> None:
    assert analyzed.get("/runs/nope/report").status_code == 404
    assert analyzed.get("/apps/APP-999").status_code == 404


def test_get_before_any_run_is_a_clear_404(client: TestClient) -> None:
    resp = client.get("/apps/APP-001")

    assert resp.status_code == 404
    assert "POST /analyze" in resp.json()["detail"]
