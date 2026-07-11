"""Golden-value scoring tests (Phase 5, Section 7).

Every expected number here is hand-computed from the Section 7 formula, then
asserted against :mod:`sbom_analyzer.scoring.risk`. This is the single source of
truth shared by the generator and the analyzer, so a drift here breaks the whole
metric surface — hence exact goldens rather than property checks.

Formula recap (per dependency):
    base_vuln  = max over CVEs of (cvss/10)*(0.6 if patch else 1.0)*exploit*100
    exploit    = calls_vulnerable_function 1.0 | imports_only 0.85 | not_referenced 0.7
    transitive = nearest_base * 0.7**hop   (only when base_vuln == 0)
    license    = conflict 80 | review 40 | ok 0
    maint      = min(40, max(0, age_years - 2) * 15)
    risk       = clamp(max(base, transitive) + 0.5*license + 0.5*maint, 0, 100)
"""

from __future__ import annotations

from datetime import date

import pytest

from sbom_analyzer.scoring.risk import (
    CveScoreInput,
    clamp,
    maintenance_penalty_for,
    score_application,
    score_dependency,
    severity_from_score,
    transitive_component,
    vulnerability_component,
)

TODAY = date(2026, 4, 15)
FRESH = TODAY  # age 0 — no maintenance penalty


# --------------------------------------------------------------------------- #
# Per-dependency goldens
# --------------------------------------------------------------------------- #
def test_worst_case_direct_critical_vuln() -> None:
    # cvss 10.0, no patch (1.0), calls_vulnerable_function (1.0):
    #   base = 1.0 * 1.0 * 1.0 * 100 = 100
    s = score_dependency(
        cves=[CveScoreInput(10.0, False)],
        usage_signal="calls_vulnerable_function",
        license_outcome="ok",
        last_updated=FRESH,
        today=TODAY,
    )
    assert s.base_vuln == pytest.approx(100.0)
    assert s.transitive_vuln == 0.0
    assert s.risk_score == pytest.approx(100.0)
    assert s.severity == "critical"


def test_patched_vuln_imports_only() -> None:
    # cvss 7.5, patch (0.6), imports_only (0.85):
    #   base = 0.75 * 0.6 * 0.85 * 100 = 38.25
    s = score_dependency(
        cves=[CveScoreInput(7.5, True)],
        usage_signal="imports_only",
        license_outcome="ok",
        last_updated=FRESH,
        today=TODAY,
    )
    assert s.base_vuln == pytest.approx(38.25)
    assert s.risk_score == pytest.approx(38.25)
    assert s.severity == "medium"


def test_license_conflict_plus_stale_no_vuln() -> None:
    # No CVE. Conflict license (80) and exactly 4.0 years stale.
    #   maint = min(40, (4-2)*15) = 30
    #   risk  = 0 + 0.5*80 + 0.5*30 = 40 + 15 = 55
    last_updated = date.fromordinal(TODAY.toordinal() - 1461)  # 4 * 365.25 days
    s = score_dependency(
        cves=[],
        usage_signal="not_referenced",
        license_outcome="conflict",
        last_updated=last_updated,
        today=TODAY,
    )
    assert s.base_vuln == 0.0
    assert s.license_penalty == pytest.approx(80.0)
    assert s.maintenance_penalty == pytest.approx(30.0)
    assert s.risk_score == pytest.approx(55.0)
    assert s.severity == "high"


def test_transitive_only_one_hop() -> None:
    # Clean itself; nearest vulnerable descendant base 100, one hop:
    #   transitive = 100 * 0.7 = 70
    s = score_dependency(
        cves=[],
        usage_signal="not_referenced",
        license_outcome="ok",
        last_updated=FRESH,
        today=TODAY,
        nearest_descendant_base_vuln=100.0,
        transitive_hop_distance=1,
    )
    assert s.base_vuln == 0.0
    assert s.transitive_vuln == pytest.approx(70.0)
    assert s.risk_score == pytest.approx(70.0)
    assert s.severity == "high"


def test_direct_vuln_suppresses_transitive() -> None:
    # base = 0.6 * 0.6 * 1.0 * 100 = 36; a vulnerable descendant is present but
    # transitive only applies to deps that are clean themselves.
    s = score_dependency(
        cves=[CveScoreInput(6.0, True)],
        usage_signal="calls_vulnerable_function",
        license_outcome="ok",
        last_updated=FRESH,
        today=TODAY,
        nearest_descendant_base_vuln=100.0,
        transitive_hop_distance=1,
    )
    assert s.base_vuln == pytest.approx(36.0)
    assert s.transitive_vuln == 0.0
    assert s.risk_score == pytest.approx(36.0)
    assert s.severity == "medium"


# --------------------------------------------------------------------------- #
# Component / band helpers
# --------------------------------------------------------------------------- #
def test_maintenance_penalty_is_capped() -> None:
    # ~10 years stale → (10-2)*15 = 120, capped at 40.
    assert maintenance_penalty_for(date(2016, 1, 1), TODAY) == 40.0
    # Not yet stale (< 2 years) → 0.
    assert maintenance_penalty_for(date(2025, 1, 1), TODAY) == 0.0


def test_transitive_decays_with_distance() -> None:
    assert transitive_component(100.0, 1) == pytest.approx(70.0)
    assert transitive_component(100.0, 2) == pytest.approx(49.0)
    assert transitive_component(100.0, 3) == pytest.approx(34.3)
    assert transitive_component(0.0, 1) == 0.0
    assert transitive_component(100.0, 0) == 0.0


def test_vulnerability_component_worst_wins() -> None:
    cves = [CveScoreInput(4.0, True), CveScoreInput(9.0, False)]
    # worst = 0.9 * 1.0 * 0.7 (not_referenced) * 100 = 63
    assert vulnerability_component(cves, "not_referenced") == pytest.approx(63.0)


def test_severity_bands() -> None:
    assert severity_from_score(0.0) == "none"
    assert severity_from_score(0.01) == "low"
    assert severity_from_score(24.99) == "low"
    assert severity_from_score(25.0) == "medium"
    assert severity_from_score(49.99) == "medium"
    assert severity_from_score(50.0) == "high"
    assert severity_from_score(74.99) == "high"
    assert severity_from_score(75.0) == "critical"
    assert severity_from_score(100.0) == "critical"


def test_clamp_bounds() -> None:
    assert clamp(-5.0) == 0.0
    assert clamp(150.0) == 100.0
    assert clamp(42.0) == 42.0


# --------------------------------------------------------------------------- #
# Per-application goldens (Section 7.4)
# --------------------------------------------------------------------------- #
def test_app_score_mixed_portfolio() -> None:
    # dep_scores: max=100, top5 mean = (100+80+60+40+20)/5 = 60,
    # high_count (critical|high) = 3 → min(100, 20*3) = 60
    # app_raw = 0.5*100 + 0.3*60 + 0.2*60 = 50 + 18 + 12 = 80
    # business_criticality high → *1.1 = 88.0
    scores = [100.0, 80.0, 60.0, 40.0, 20.0, 0.0]
    sevs = ["critical", "critical", "high", "medium", "low", "none"]
    assert score_application(scores, sevs, "high") == pytest.approx(88.0)


def test_app_score_clamps_at_100() -> None:
    # All maxed: app_raw = 50 + 30 + 20 = 100, *1.2 (critical) = 120 → clamp 100.
    scores = [100.0] * 6
    sevs = ["critical"] * 6
    assert score_application(scores, sevs, "critical") == pytest.approx(100.0)


def test_app_score_low_criticality_discount() -> None:
    # max=10, top5 mean = 10/3, high_count 0.
    # app_raw = 0.5*10 + 0.3*(10/3) + 0 = 5 + 1 = 6.0, *0.9 (low) = 5.4
    scores = [10.0, 0.0, 0.0]
    sevs = ["low", "none", "none"]
    assert score_application(scores, sevs, "low") == pytest.approx(5.4)


def test_app_score_empty_is_zero() -> None:
    assert score_application([], [], "high") == 0.0
