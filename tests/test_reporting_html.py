"""Phase 7 — the HTML view must be faithful, safe, and complete."""

from __future__ import annotations

from datetime import date, datetime

import pytest

from sbom_analyzer.models.entities import CvssSeverity, Ecosystem, LicenseOutcome
from sbom_analyzer.models.findings import (
    AnalysisReport,
    AppRiskReport,
    AttackPath,
    DependencyFinding,
    GlobalSummary,
    MaintenanceStatus,
    MatchedVulnerability,
    RemediationPlaybook,
    RiskType,
    RiskyDependencyRef,
    Severity,
)
from sbom_analyzer.reporting.html import build_context, render_html, write_html


def _finding(
    dep_id: str,
    *,
    score: float,
    severity: Severity,
    risk_types: list[RiskType],
    narrative: str | None = None,
    paths: list[AttackPath] | None = None,
) -> DependencyFinding:
    return DependencyFinding(
        dependency_id=dep_id,
        app_id="APP-001",
        library_name="jackson-databind",
        version="2.14.1",
        ecosystem=Ecosystem.maven,
        license="Apache-2.0",
        risk_score=score,
        severity=severity,
        risk_types=risk_types,
        matched_cves=[
            MatchedVulnerability(
                cve_id="CVE-2024-0001",
                cvss_score=9.1,
                cvss_severity=CvssSeverity.critical,
                affected_versions=">=2.0,<2.15.0",
                patch_available=True,
                fixed_version="2.15.0",
                cve_score=91.0,
            )
        ]
        if RiskType.vulnerable in risk_types
        else [],
        license_outcome=LicenseOutcome.ok,
        maintenance=MaintenanceStatus(
            last_updated=date(2021, 1, 1), age_years=5.3, is_stale=True
        ),
        attack_paths=paths or [],
        narrative=narrative,
        remediation=RemediationPlaybook(steps=["Upgrade to 2.15.0"], priority="P1"),
    )


@pytest.fixture
def report() -> AnalysisReport:
    risky = _finding(
        "DEP-1",
        score=88.0,
        severity=Severity.critical,
        risk_types=[RiskType.vulnerable, RiskType.unmaintained],
        narrative="Deserialization of untrusted input reaches the gadget chain.",
        paths=[
            AttackPath(
                app_id="APP-001",
                path=["APP-001", "DEP-2", "DEP-1"],
                vulnerable_dependency_id="DEP-1",
                cve_id="CVE-2024-0001",
            )
        ],
    )
    clean = _finding("DEP-9", score=0.0, severity=Severity.none, risk_types=[RiskType.clean])
    clean.library_name = "requests"
    clean.version = "2.31.0"

    quiet_app = AppRiskReport(
        app_id="APP-002",
        name="Quiet Service",
        business_criticality="low",
        app_score=5.0,
        severity=Severity.low,
        findings=[],
    )
    loud_app = AppRiskReport(
        app_id="APP-001",
        name="Payments API",
        business_criticality="critical",
        app_score=91.5,
        severity=Severity.critical,
        findings=[risky, clean],
    )
    return AnalysisReport(
        run_id="run-test",
        generated_at=datetime(2026, 4, 15),
        apps=[quiet_app, loud_app],  # deliberately NOT in risk order
        summary=GlobalSummary(
            totals_per_risk_type={RiskType.vulnerable: 1, RiskType.unmaintained: 1},
            top_riskiest=[
                RiskyDependencyRef(
                    dependency_id="DEP-1",
                    app_id="APP-001",
                    library_name="jackson-databind",
                    version="2.14.1",
                    risk_score=88.0,
                    severity=Severity.critical,
                )
            ],
            dedup_note="1 vulnerable library/version pair spans multiple apps.",
        ),
    )


def test_apps_are_sorted_by_risk_descending(report: AnalysisReport) -> None:
    ctx = build_context(report)
    assert [a.app_id for a in ctx["apps"]] == ["APP-001", "APP-002"]


def test_totals_are_string_keyed_and_zero_filled(report: AnalysisReport) -> None:
    totals = build_context(report)["totals"]
    assert totals["vulnerable"] == 1
    # A risk type with no hits must render "0", not disappear.
    assert totals["license_conflict"] == 0


def test_attack_path_hops_render_as_library_names_not_ids(report: AnalysisReport) -> None:
    html = render_html(report)
    assert "Payments API" in html  # the app node, by name
    assert "jackson-databind 2.14.1" in html  # the victim node, by label


def test_html_shows_severity_scores_paths_narrative_and_remediation(
    report: AnalysisReport,
) -> None:
    html = render_html(report)
    assert "sev-critical" in html  # traffic-light class
    assert "91.5" in html and "88.0" in html  # app score + dep score
    assert "CVE-2024-0001" in html
    assert "Deserialization of untrusted input" in html  # Reasoner C narrative
    assert "Upgrade to 2.15.0" in html  # Reasoner D playbook
    assert ">P1<" in html


def test_clean_findings_are_rolled_up_not_dropped(report: AnalysisReport) -> None:
    html = render_html(report)
    assert "1 clean dependency" in html
    assert "requests" in html


def test_llm_narrative_is_escaped(report: AnalysisReport) -> None:
    """Model output is untrusted text: it must never reach the page as markup."""
    report.apps[1].findings[0].narrative = "<script>alert('xss')</script>"
    html = render_html(report)
    assert "<script>alert" not in html
    assert "&lt;script&gt;" in html


def test_provenance_banner_reflects_the_run(report: AnalysisReport) -> None:
    assert "fully deterministic" in render_html(report)

    report.llm_provider, report.llm_affects_score = "openai", False
    assert "advisory only" in render_html(report)

    report.llm_affects_score = True
    assert "feeding risk scores" in render_html(report)


def test_a_degraded_llm_run_is_not_passed_off_as_llm_output(
    report: AnalysisReport,
) -> None:
    """`llm_provider=openai` only means *configured*. If every call 402s, the
    narratives are deterministic templates and the page must not claim otherwise."""
    report.llm_provider = "openai"
    report.llm_calls, report.llm_fallbacks = 28, 28
    finding = report.apps[1].findings[0]
    finding.llm_enriched = False  # its calls fell back

    html = render_html(report)

    assert "every LLM call failed" in html
    assert "deterministic template" in html
    assert "generated by openai" not in html


def test_a_successful_llm_finding_is_credited(report: AnalysisReport) -> None:
    report.llm_provider = "openai"
    report.llm_calls, report.llm_fallbacks = 28, 0
    report.apps[1].findings[0].llm_enriched = True

    html = render_html(report)

    assert "generated by openai" in html
    assert "fell back" not in html


def test_write_html_is_self_contained(report: AnalysisReport, tmp_path) -> None:
    path = write_html(report, tmp_path / "report.html")
    html = path.read_text(encoding="utf-8")
    assert html.startswith("<!doctype html>")
    # No external fetches: the file has to open offline, from disk, in one piece.
    assert "src=\"http" not in html and "href=\"http" not in html
    assert "<style>" in html
