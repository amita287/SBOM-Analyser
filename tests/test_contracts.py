"""The dataset's on-disk shape maps onto the codebase's vocabulary."""

from __future__ import annotations

from datetime import date

import pytest

from sbom_analyzer.models.entities import (
    Deployment,
    LicenseModel,
    LicenseOutcome,
)
from tests.conftest import make_app, make_cve, make_dep, make_rules


class TestAliases:
    """The CSV/JSON column names are translated once, here, and nowhere else."""

    def test_application_aliases(self):
        app = make_app()
        assert app.business_criticality.value == "high"  # from `criticality: HIGH`
        assert app.owner == "Sarah Chen"  # from `business_owner`
        assert app.environment is Deployment.cloud  # from `deployment`

    def test_dependency_aliases(self):
        dep = make_dep()
        assert dep.dependency_id == "DEP-0001"  # from `dep_id`
        assert dep.app_id == "APP-001"  # from `application_id`
        assert dep.library_name == "micrometer-core"  # from `library`
        assert dep.last_updated == date(2025, 1, 30)

    def test_vulnerability_aliases_and_case(self):
        cve = make_cve()
        assert cve.library_name == "micrometer-core"  # from `library`
        assert cve.cvss_severity.value == "medium"  # from `severity: MEDIUM`
        assert cve.exploitability.value == "low"  # from `LOW`

    def test_distributed_is_derived_from_license_model(self):
        assert make_app(license_model="proprietary").distributed is True
        assert make_app(license_model="internal-only").distributed is False


class TestTransitiveDepsColumn:
    """`transitive_deps` is a `lib:ver;lib:ver` string that has to become edges."""

    def test_parses_multiple_children(self):
        dep = make_dep(transitive_deps="jackson-core:4.9.0;aws-sdk-s3:3.4.2")
        assert [(c.library_name, c.version) for c in dep.transitive_children] == [
            ("jackson-core", "4.9.0"),
            ("aws-sdk-s3", "3.4.2"),
        ]

    def test_empty_column_is_no_children(self):
        assert make_dep(transitive_deps="").transitive_children == []

    def test_version_is_split_from_the_right(self):
        """A library name could contain a colon; a version never does."""
        dep = make_dep(transitive_deps="org:group:core:1.2.3")
        (child,) = dep.transitive_children
        assert child.library_name == "org:group:core"
        assert child.version == "1.2.3"


class TestLicenceResolution:
    """The SBOM and the rule book spell licences differently. That must not
    silently mean 'no rule found, therefore fine'."""

    def test_alias_maps_sbom_spelling_to_rule_book(self, rules):
        # SBOM says `GPL-3.0`; the rule book only knows `GPL-3.0-only`.
        rule = rules.lookup("GPL-3.0")
        assert rule is not None and rule.viral

    def test_viral_in_a_proprietary_product_is_a_conflict(self, rules):
        assert rules.resolve("GPL-3.0", distributed=True) is LicenseOutcome.conflict

    def test_same_licence_internal_only_is_fine(self, rules):
        """The regression that matters: a GPL library in an internal tool is not
        a conflict, and calling it one is a false positive with legal weight."""
        assert rules.resolve("GPL-3.0", distributed=False) is LicenseOutcome.ok

    def test_undeclared_is_unknown_not_conflict(self, rules):
        assert rules.resolve("UNKNOWN", distributed=True) is LicenseOutcome.unknown
        assert rules.resolve("", distributed=True) is LicenseOutcome.unknown

    def test_declared_but_unrecognised_is_ok(self, rules):
        """`Dual-MIT/Commercial` appears on 66 dependencies and in no rule.

        Declared-but-unrecognised is NOT undeclared. Treating it as unknown would
        flag 66 healthy dependencies and wreck the false-positive rate.
        """
        assert (
            rules.resolve("Dual-MIT/Commercial", distributed=True) is LicenseOutcome.ok
        )
