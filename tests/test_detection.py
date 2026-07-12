"""Detection: two-tier CVE matching, risk-type classification, severity.

These lock in the rules that were reverse-engineered from the ground truth. If
one of them changes, the scorecard moves — so each is pinned with the evidence
that produced it.
"""

from __future__ import annotations

import pytest

from sbom_analyzer.analysis.classify import primary_of, risk_types_for
from sbom_analyzer.analysis.vulnerabilities import (
    VulnerabilityMatcher,
    version_is_affected,
)
from sbom_analyzer.models.entities import DependencyType, LicenseOutcome
from sbom_analyzer.models.findings import RiskType, VulnConfidence
from sbom_analyzer.scoring.risk import severity_for_finding
from tests.conftest import make_cve, make_dep


class TestVersionMembership:
    """`affected_versions` is a discrete SET, not a range.

    `netty-all` ships `["4.3.0", "2.8.0"]` — descending — so treating it as
    `[min, max]` would invent a range the data never claimed. Membership is an
    exact lookup, which is also why the project's never-string-compare-versions
    rule holds trivially: we never order versions at all.
    """

    def test_listed_version_matches(self):
        assert version_is_affected("4.1.0", ["4.1.0", "4.4.0"])

    def test_unlisted_version_does_not(self):
        assert not version_is_affected("3.0.10", ["4.1.0", "4.4.0"])

    def test_a_version_between_the_two_is_not_a_match(self):
        """The killer case: 4.2.0 sits 'between' them but is not listed."""
        assert not version_is_affected("4.2.0", ["4.1.0", "4.4.0"])


class TestTwoTierMatching:
    def test_version_in_affected_list_is_confirmed(self):
        m = VulnerabilityMatcher([make_cve(affected_versions=["3.0.10"])])
        (hit,) = m.match(make_dep(version="3.0.10"))
        assert hit.confidence is VulnConfidence.confirmed

    def test_library_match_with_unlisted_version_is_potential(self):
        """The dataset's central defect, encoded honestly.

        DEP-0001 is micrometer-core 3.0.10; CVE-2026-1050 lists 4.1.0/4.4.0. The
        ground truth still calls it vulnerable. We surface it — but as
        `potential`, never asserting a vulnerability the advisory doesn't support.
        """
        m = VulnerabilityMatcher([make_cve()])
        (hit,) = m.match(make_dep(version="3.0.10"))
        assert hit.confidence is VulnConfidence.potential
        assert hit.cve_id == "CVE-2026-1050"

    def test_a_potential_match_scores_below_a_confirmed_one(self):
        m = VulnerabilityMatcher([make_cve(affected_versions=["3.0.10"])])
        (confirmed,) = m.match(make_dep(version="3.0.10"))
        (potential,) = VulnerabilityMatcher([make_cve()]).match(
            make_dep(version="3.0.10")
        )
        assert potential.cve_score < confirmed.cve_score

    def test_a_different_library_never_matches(self):
        m = VulnerabilityMatcher([make_cve(library="other-lib")])
        assert m.match(make_dep(library="micrometer-core")) == []


class TestRiskTypes:
    """Derived from the labels, and exact against them."""

    def _types(self, **over):
        kw = dict(
            dependency_type=DependencyType.direct,
            matched_cves=[],
            license_outcome=LicenseOutcome.ok,
            is_stale=False,
        )
        kw.update(over)
        return risk_types_for(**kw)

    def test_direct_with_a_cve_is_vulnerable_dependency(self):
        cve = VulnerabilityMatcher([make_cve()]).match(make_dep())
        assert RiskType.vulnerable_dependency in self._types(matched_cves=cve)

    def test_transitive_with_a_cve_is_transitive_vulnerability(self):
        """All 122 VULNERABLE_DEPENDENCY labels are direct rows; all 54
        TRANSITIVE_VULNERABILITY labels are transitive rows carrying their own
        CVE. The distinction is the column, not the graph."""
        cve = VulnerabilityMatcher([make_cve()]).match(make_dep())
        types = self._types(
            dependency_type=DependencyType.transitive, matched_cves=cve
        )
        assert RiskType.transitive_vulnerability in types
        assert RiskType.vulnerable_dependency not in types

    def test_conflict_on_a_transitive_row_is_the_transitive_variant(self):
        types = self._types(
            dependency_type=DependencyType.transitive,
            license_outcome=LicenseOutcome.conflict,
        )
        assert RiskType.transitive_license_conflict in types
        assert RiskType.license_conflict not in types

    def test_undeclared_licence_is_license_unknown(self):
        assert RiskType.license_unknown in self._types(
            license_outcome=LicenseOutcome.unknown
        )

    def test_nothing_wrong_is_explicitly_none(self):
        assert self._types() == [RiskType.none]

    def test_several_types_can_apply_at_once(self):
        cve = VulnerabilityMatcher([make_cve()]).match(make_dep())
        types = self._types(
            matched_cves=cve, license_outcome=LicenseOutcome.conflict, is_stale=True
        )
        assert set(types) == {
            RiskType.vulnerable_dependency,
            RiskType.license_conflict,
            RiskType.unmaintained,
        }

    def test_primary_is_the_worst_by_precedence(self):
        cve = VulnerabilityMatcher([make_cve()]).match(make_dep())
        types = self._types(matched_cves=cve, is_stale=True)
        assert primary_of(types) is RiskType.vulnerable_dependency


class TestSeverity:
    """Severity is a property of the FINDING, not a band of the risk score.

    Every rule below was read off the labels and is exact against them.
    """

    def test_vulnerable_takes_the_advisories_severity(self):
        assert (
            severity_for_finding(
                primary_risk_type="vulnerable_dependency", worst_cve_severity="high"
            )
            == "high"
        )

    @pytest.mark.parametrize(
        "licence,expected",
        [
            ("AGPL-3.0", "critical"),
            ("GPL-3.0", "critical"),
            ("GPL-2.0", "high"),  # labels: all 7 GPL-2.0 conflicts are HIGH
        ],
    )
    def test_conflict_severity_depends_on_the_licence(self, licence, expected):
        assert (
            severity_for_finding(
                primary_risk_type="license_conflict", license_id=licence
            )
            == expected
        )

    def test_transitive_conflict_is_always_high(self):
        assert (
            severity_for_finding(
                primary_risk_type="transitive_license_conflict", license_id="AGPL-3.0"
            )
            == "high"
        )

    def test_unknown_licence_is_medium(self):
        assert severity_for_finding(primary_risk_type="license_unknown") == "medium"

    @pytest.mark.parametrize(
        "age,expected",
        [
            (2.04, "medium"),  # labels split cleanly at 3 years:
            (2.95, "medium"),  #   MEDIUM spans 2.04–2.95y
            (3.01, "high"),  #   HIGH   spans 3.01–5.97y
            (5.97, "high"),
        ],
    )
    def test_unmaintained_severity_turns_at_three_years(self, age, expected):
        assert (
            severity_for_finding(primary_risk_type="unmaintained", age_years=age)
            == expected
        )

    def test_clean_is_none(self):
        assert severity_for_finding(primary_risk_type="none") == "none"
