"""Graph, scoring, and the end-to-end pipeline over the real dataset."""

from __future__ import annotations

from datetime import date

import pytest

from sbom_analyzer.graph.builder import (
    NODE_KIND_APP,
    NODE_KIND_DEP,
    NODE_KIND_EXT,
    build_graph,
)
from sbom_analyzer.graph.traversal import descendants_of, paths_to_vulnerable
from sbom_analyzer.models.findings import RiskType
from sbom_analyzer.scoring.risk import (
    CveScoreInput,
    maintenance_penalty_for,
    score_dependency,
    vulnerability_component,
)
from tests.conftest import TODAY, make_app, make_dep


class TestGraph:
    def test_dependencies_hang_off_their_application(self):
        g = build_graph([make_app()], [make_dep()])
        assert g.nodes["APP-001"]["kind"] == NODE_KIND_APP
        assert g.nodes["DEP-0001"]["kind"] == NODE_KIND_DEP
        assert g.has_edge("APP-001", "DEP-0001")

    def test_transitive_children_become_external_nodes(self):
        """The children in `transitive_deps` are phantoms — none of the 372 has an
        SBOM row. They are real structure, so they are drawn, but they are never
        scored, because the ground truth never scores them either."""
        g = build_graph([make_app()], [make_dep(transitive_deps="tomcat:2.4.0")])
        ext = [n for n, d in g.nodes(data=True) if d["kind"] == NODE_KIND_EXT]
        assert len(ext) == 1
        assert g.has_edge("DEP-0001", ext[0])

    def test_same_library_in_two_apps_is_two_nodes(self):
        """Collapsing them would fuse two apps' subgraphs into one component that
        no longer reflects the SBOM."""
        apps = [make_app(), make_app(app_id="APP-002", name="Other")]
        deps = [
            make_dep(transitive_deps="tomcat:2.4.0"),
            make_dep(
                dep_id="DEP-0002", application_id="APP-002", transitive_deps="tomcat:2.4.0"
            ),
        ]
        g = build_graph(apps, deps)
        ext = [n for n, d in g.nodes(data=True) if d["kind"] == NODE_KIND_EXT]
        assert len(ext) == 2

    def test_unknown_application_is_a_loud_failure(self):
        with pytest.raises(ValueError, match="not a known node"):
            build_graph([make_app()], [make_dep(application_id="APP-999")])

    def test_paths_reach_a_vulnerable_external(self):
        g = build_graph([make_app()], [make_dep(transitive_deps="tomcat:2.4.0")])
        ext = next(n for n, d in g.nodes(data=True) if d["kind"] == NODE_KIND_EXT)
        paths = paths_to_vulnerable(g, "APP-001", {ext})
        assert paths == [["APP-001", "DEP-0001", ext]]

    def test_descendants(self):
        g = build_graph([make_app()], [make_dep(transitive_deps="tomcat:2.4.0")])
        assert len(descendants_of(g, "APP-001")) == 2


class TestScoring:
    def test_worst_cve_wins(self):
        low = CveScoreInput(cvss_score=3.0, patch_available=False)
        high = CveScoreInput(cvss_score=9.0, patch_available=False)
        assert vulnerability_component([low, high]) == vulnerability_component([high])

    def test_confidence_reduces_the_score(self):
        confirmed = CveScoreInput(
            cvss_score=9.0, patch_available=False, confidence="confirmed"
        )
        potential = CveScoreInput(
            cvss_score=9.0, patch_available=False, confidence="potential"
        )
        assert vulnerability_component([potential]) < vulnerability_component(
            [confirmed]
        )

    def test_exploitability_scales_the_score(self):
        hi = CveScoreInput(cvss_score=8.0, patch_available=False, exploitability="high")
        lo = CveScoreInput(cvss_score=8.0, patch_available=False, exploitability="none")
        assert vulnerability_component([lo]) < vulnerability_component([hi])

    def test_an_available_patch_lowers_the_score(self):
        unpatched = CveScoreInput(cvss_score=8.0, patch_available=False)
        patched = CveScoreInput(cvss_score=8.0, patch_available=True)
        assert vulnerability_component([patched]) < vulnerability_component([unpatched])

    def test_fresh_dependency_has_no_maintenance_penalty(self):
        assert maintenance_penalty_for(date(2026, 1, 1), TODAY) == 0.0

    def test_stale_dependency_is_penalised_and_capped(self):
        assert maintenance_penalty_for(date(2023, 1, 1), TODAY) > 0.0
        assert maintenance_penalty_for(date(1990, 1, 1), TODAY) == 40.0

    def test_score_is_clamped_to_100(self):
        s = score_dependency(
            cves=[CveScoreInput(cvss_score=10.0, patch_available=False, exploitability="high")],
            license_outcome="conflict",
            last_updated=date(1999, 1, 1),
            today=TODAY,
        )
        assert s.risk_score == 100.0


class TestRealRun:
    """The pipeline over the shipped dataset. These numbers are load-bearing."""

    def test_every_dependency_is_scored(self, real_report, dataset):
        findings = [f for a in real_report.apps for f in a.findings]
        assert len(findings) == len(dataset.dependencies) == 500

    def test_no_llm_touched_this_run(self, real_report):
        assert real_report.llm_provider == "none"
        assert real_report.llm_calls == 0
        assert all(
            not f.llm_enriched for a in real_report.apps for f in a.findings
        )

    def test_prose_exists_for_every_at_risk_finding_without_an_llm(self, real_report):
        """The deterministic fallbacks are the point: LLM_PROVIDER=none must still
        produce a full report."""
        at_risk = [f for a in real_report.apps for f in a.findings if f.is_risk]
        assert at_risk
        assert all(f.remediation and f.remediation.steps for f in at_risk)

    def test_every_finding_has_exactly_one_primary_type(self, real_report):
        for a in real_report.apps:
            for f in a.findings:
                assert f.primary_risk_type in f.risk_types

    def test_vulnerable_rows_are_direct_and_transitive_rows_are_not(self, real_report):
        """The rule the ground truth actually encodes."""
        for a in real_report.apps:
            for f in a.findings:
                if RiskType.vulnerable_dependency in f.risk_types:
                    assert f.dependency_type.value == "direct"
                if RiskType.transitive_vulnerability in f.risk_types:
                    assert f.dependency_type.value == "transitive"

    def test_no_confirmed_cves_in_this_dataset(self, real_report):
        """Not a bug — the headline finding.

        No dependency version appears in its own library's `affected_versions`.
        Every CVE match is therefore `potential`. If this ever fails, the dataset
        was fixed upstream and the two-tier caveats can be revisited.
        """
        confirmed = [
            c
            for a in real_report.apps
            for f in a.findings
            for c in f.matched_cves
            if c.is_confirmed
        ]
        assert confirmed == []

    def test_run_is_deterministic(self, dataset):
        from sbom_analyzer.reporting.report import build_report

        a = build_report(dataset, today=TODAY).model_dump_json()
        b = build_report(dataset, today=TODAY).model_dump_json()
        assert a == b
