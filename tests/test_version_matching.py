"""Vulnerability version-range matching tests (Phase 4).

Version matching MUST use ``packaging.specifiers.SpecifierSet`` — never raw
string comparison — and must exclude ``backported_patch_builds`` (FP traps).
"""

from __future__ import annotations

from datetime import date

from sbom_analyzer.analysis.vulnerabilities import (
    VulnerabilityMatcher,
    base_vuln_score,
    is_backported_safe,
    is_vulnerable,
    real_hits,
    version_matches,
)
from sbom_analyzer.models.entities import Dependency, Vulnerability


# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #
def _dep(version: str, *, library: str = "log4j-core", usage: str = "imports_only") -> Dependency:
    return Dependency(
        dependency_id="DEP-T",
        app_id="APP-T",
        library_name=library,
        version=version,
        license="MIT",
        dependency_type="direct",
        parent_dependency_id="",
        last_updated=date(2025, 6, 1),
        ecosystem="maven",
        usage_signal=usage,
    )


def _cve(
    *,
    library: str = "log4j-core",
    affected: str = ">=2.0,<2.15.0",
    backported: list[str] | None = None,
    cvss: float = 9.8,
    severity: str = "critical",
    patch: bool = True,
) -> Vulnerability:
    return Vulnerability(
        cve_id="CVE-TEST-0001",
        library_name=library,
        affected_versions=affected,
        cvss_score=cvss,
        cvss_severity=severity,
        patch_available=patch,
        fixed_version="2.15.0",
        vulnerable_function="Log.lookup",
        backported_patch_builds=backported or [],
        description="test",
    )


# --------------------------------------------------------------------------- #
# version_matches — the required cases
# --------------------------------------------------------------------------- #
def test_in_range_matches() -> None:
    assert version_matches("2.14.1", ">=2.0,<2.15.0") is True


def test_upper_bound_is_exclusive() -> None:
    assert version_matches("2.15.0", ">=2.0,<2.15.0") is False


def test_below_range_does_not_match() -> None:
    assert version_matches("1.9.9", ">=2.0,<2.15.0") is False


def test_string_comparison_pitfall() -> None:
    # As raw strings, "2.9" > "2.14" is True and "2.9" < "2.100" is False —
    # both wrong. Real version semantics must win.
    assert "2.9" > "2.14"  # the trap: lexicographic string ordering
    assert version_matches("2.9", ">=2.0,<2.14") is True  # 2.9 < 2.14 numerically
    assert version_matches("2.14", ">=2.0,<2.14") is False  # boundary, exclusive
    assert version_matches("2.100", ">=2.0,<2.101") is True  # 2.100 > 2.99


def test_exact_pin_specifier() -> None:
    assert version_matches("2.14.1", "==2.14.1") is True
    assert version_matches("2.14.2", "==2.14.1") is False


def test_invalid_inputs_are_non_matches_not_crashes() -> None:
    assert version_matches("not-a-version", ">=2.0,<3.0") is False
    assert version_matches("2.0.0", "this is not a specifier") is False


# --------------------------------------------------------------------------- #
# Backported / false-positive exclusion
# --------------------------------------------------------------------------- #
def test_is_backported_safe_exact_membership() -> None:
    assert is_backported_safe("2.0.0", ["2.0.0"]) is True
    assert is_backported_safe("2.0.1", ["2.0.0"]) is False
    assert is_backported_safe("2.0.0", []) is False


def test_backported_build_in_range_is_false_positive() -> None:
    # FP trap: version is inside the affected range AND explicitly backported.
    matcher = VulnerabilityMatcher([_cve(affected=">=2.0.0,<2.1.0", backported=["2.0.0"])])
    matched = matcher.match(_dep("2.0.0"))

    assert len(matched) == 1
    assert matched[0].is_false_positive is True
    assert matched[0].cve_score == 0.0
    assert is_vulnerable(matched) is False        # the bait must not read as vuln
    assert real_hits(matched) == []
    assert base_vuln_score(matched) == 0.0


def test_in_range_non_backported_is_a_real_hit() -> None:
    # Same CVE, a sibling build that was NOT backported → genuine vulnerability.
    matcher = VulnerabilityMatcher([_cve(affected=">=2.0.0,<2.1.0", backported=["2.0.0"])])
    matched = matcher.match(_dep("2.0.5"))

    assert len(matched) == 1
    assert matched[0].is_false_positive is False
    assert matched[0].cve_score > 0.0
    assert is_vulnerable(matched) is True


# --------------------------------------------------------------------------- #
# Matcher behaviour
# --------------------------------------------------------------------------- #
def test_no_match_for_unrelated_library() -> None:
    matcher = VulnerabilityMatcher([_cve(library="some-other-lib")])
    assert matcher.match(_dep("2.14.1", library="log4j-core")) == []


def test_worst_cve_wins_and_sorted() -> None:
    # Two CVEs cover the version; the higher CVSS must sort first and drive base_vuln.
    low = _cve(affected=">=2.0,<3.0", cvss=4.0, severity="medium")
    low = low.model_copy(update={"cve_id": "CVE-LOW"})
    high = _cve(affected=">=2.0,<3.0", cvss=9.8, severity="critical")
    high = high.model_copy(update={"cve_id": "CVE-HIGH"})

    matcher = VulnerabilityMatcher([low, high])
    matched = matcher.match(_dep("2.5.0", usage="calls_vulnerable_function"))

    assert [m.cve_id for m in matched] == ["CVE-HIGH", "CVE-LOW"]
    # calls_vulnerable_function=1.0, patch_available lowers to 0.6: 0.98*0.6*1.0*100
    assert base_vuln_score(matched) == 9.8 / 10.0 * 0.6 * 1.0 * 100.0
