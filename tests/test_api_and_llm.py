"""The HTTP surface, and the LLM's deterministic fallbacks."""

from __future__ import annotations

import collections

import pytest
from fastapi.testclient import TestClient

from sbom_analyzer.api.main import app
from sbom_analyzer.config import Settings
from sbom_analyzer.llm.client import LLMClient
from sbom_analyzer.llm.reasoners import build_remediation, narrate_attack_path
from tests.conftest import make_app, make_cve, make_dep


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


class TestApi:
    def test_health(self, client):
        assert client.get("/health").json()["status"] == "ok"

    def test_run_summary_counts_match_the_report(self, client):
        run = client.get("/runs/latest").json()
        assert run["apps"] == 10
        assert run["findings"] == 500
        assert run["at_risk"] + run["totals_per_risk_type"]["none"] == 500

    def test_applications_carry_the_descriptive_fields(self, client):
        apps = client.get("/applications").json()
        assert len(apps) == 10
        assert apps[0]["owner"]  # AppRiskReport drops these; the console needs them
        assert apps[0]["license_model"]

    def test_graph_has_all_three_node_kinds(self, client):
        g = client.get("/graph?app_id=APP-001").json()
        kinds = collections.Counter(n["data"]["kind"] for n in g["nodes"])
        assert kinds["application"] == 1
        assert kinds["dependency"] == 50
        assert kinds["external"] > 0  # the phantom transitive children

    def test_graph_never_rings_an_unconfirmed_match_as_a_live_cve(self, client):
        """`cve_count` drives the red ring on the canvas. Asserting a CVE the
        advisory never claimed is exactly the false alarm the confidence tier
        exists to prevent — so unconfirmed matches are counted separately."""
        g = client.get("/graph").json()
        deps = [n["data"] for n in g["nodes"] if n["data"]["kind"] == "dependency"]
        assert all(d["cve_count"] == 0 for d in deps)  # nothing is confirmed here
        assert any(d["unconfirmed_cve_count"] > 0 for d in deps)

    def test_unknown_app_is_404(self, client):
        assert client.get("/apps/APP-999").status_code == 404
        assert client.get("/graph?app_id=APP-999").status_code == 404

    def test_findings_default_excludes_clean(self, client):
        rows = client.get("/findings?limit=1000").json()
        assert rows
        assert all("none" not in f["risk_types"] for f in rows)

    def test_findings_filter_by_risk_type(self, client):
        rows = client.get("/findings?risk_type=unmaintained&limit=1000").json()
        assert rows
        assert all("unmaintained" in f["risk_types"] for f in rows)

    def test_findings_are_ranked_worst_first(self, client):
        rows = client.get("/findings?limit=50").json()
        scores = [f["risk_score"] for f in rows]
        assert scores == sorted(scores, reverse=True)

    def test_console_is_served(self, client):
        for path in ("/static/dashboard.html", "/static/graph.html", "/static/console.js"):
            assert client.get(path).status_code == 200


class TestLlmFallbacks:
    """With the LLM off, every reasoner must still return a usable result."""

    @pytest.fixture
    def off(self):
        c = LLMClient(Settings())
        assert not c.enabled
        return c

    def test_narrative_falls_back_and_makes_no_calls(self, off):
        text = narrate_attack_path(
            off,
            app=make_app(),
            path_labels=["CustomerPortal", "micrometer-core@3.0.10"],
            library_name="micrometer-core",
            version="3.0.10",
            cve=make_cve(),
            hop_distance=1,
            confirmed=True,
        )
        assert "micrometer-core" in text and "CVE-2026-1050" in text
        assert off.calls == 0

    def test_unconfirmed_narrative_does_not_assert_vulnerability(self, off):
        """The report must never claim a CVE the advisory doesn't support."""
        text = narrate_attack_path(
            off,
            app=make_app(),
            path_labels=["CustomerPortal", "micrometer-core@3.0.10"],
            library_name="micrometer-core",
            version="3.0.10",
            cve=make_cve(),
            hop_distance=1,
            confirmed=False,
        )
        assert "unconfirmed" in text.lower()

    def test_remediation_leads_with_verification_when_unconfirmed(self, off):
        """Do not tell someone to upgrade against an advisory that never named
        their version. Establish whether it applies first."""
        plan = build_remediation(
            off,
            dep=make_dep(),
            app=make_app(),
            risk_score=60.0,
            severity="high",
            risk_types=["vulnerable_dependency"],
            cve=make_cve(),
            license_outcome="ok",
            is_stale=False,
            age_years=1.0,
            confidence="potential",
        )
        assert plan.steps
        assert "confirm" in plan.steps[0].lower()

    def test_remediation_names_the_fixed_version_when_there_is_one(self, off):
        plan = build_remediation(
            off,
            dep=make_dep(),
            app=make_app(),
            risk_score=60.0,
            severity="high",
            risk_types=["vulnerable_dependency"],
            cve=make_cve(fixed_version="4.5.0", patch_available=True),
            license_outcome="ok",
            is_stale=False,
            age_years=1.0,
            confidence="confirmed",
        )
        assert any("4.5.0" in s for s in plan.steps)

    def test_unconfirmed_match_is_never_p1(self, off):
        """P1 means drop everything. An unverified library-name collision never
        earns that, however critical the application."""
        plan = build_remediation(
            off,
            dep=make_dep(),
            app=make_app(criticality="CRITICAL"),
            risk_score=40.0,
            severity="medium",
            risk_types=["vulnerable_dependency"],
            cve=make_cve(),
            license_outcome="ok",
            is_stale=False,
            age_years=1.0,
            confidence="potential",
        )
        assert plan.priority != "P1"


class TestReasonerB:
    """False-positive adjudication of POTENTIAL matches."""

    @pytest.fixture
    def off(self):
        return LLMClient(Settings())

    def test_fallback_keeps_the_finding(self, off):
        """The safe failure direction.

        When nothing can be established, a security tool must not quietly discard
        a possible vulnerability. Silence is the one answer that gets someone
        breached, so the fallback surfaces it for review instead.
        """
        from sbom_analyzer.llm.reasoners import adjudicate_false_positive

        v = adjudicate_false_positive(off, dep=make_dep(), cve=make_cve())
        assert v.is_false_positive is False
        assert "not in" in v.reasoning.lower()
        assert off.calls == 0

    def test_potentials_are_adjudicated_and_recorded(self, real_report):
        """Every potential match carries a ruling, even with the LLM off."""
        potentials = [
            c
            for a in real_report.apps
            for f in a.findings
            for c in f.matched_cves
            if not c.is_confirmed
        ]
        assert potentials
        assert all(c.adjudication for c in potentials)
        assert all(not c.adjudicated_by_llm for c in potentials)  # LLM is off

    def test_nothing_is_dismissed_without_the_score_gate(self, real_report):
        """CLAUDE.md: an LLM must never move a number that feeds a metric.

        Reasoner B *can* drop a CVE, so its ruling is only applied when
        LLM_AFFECTS_SCORE is set. With the default off, no finding may be
        dismissed — otherwise the scorecard would be measuring the model.
        """
        dismissed = [
            c
            for a in real_report.apps
            for f in a.findings
            for c in f.matched_cves
            if c.dismissed
        ]
        assert dismissed == []

    def test_status_is_potential_when_the_version_is_not_listed(self, real_report):
        from sbom_analyzer.models.findings import VulnStatus

        flagged = [
            f
            for a in real_report.apps
            for f in a.findings
            if f.matched_cves
        ]
        assert flagged
        assert all(
            f.vuln_status is VulnStatus.potential_vulnerable for f in flagged
        )
        assert all(f.is_flagged_vulnerable for f in flagged)
