"""License rule engine tests (Phase 4).

Exercises the two-step resolution — SPDX id → category → compatibility matrix —
under both distribution contexts, plus the app-aware dependency resolver.
"""

from __future__ import annotations

from datetime import date

from sbom_analyzer.analysis.licenses import (
    LicenseEngine,
    is_conflict,
    resolve_outcome,
)
from sbom_analyzer.ingestion.loaders import load_license_rules
from sbom_analyzer.models.entities import (
    Application,
    Dependency,
    LicenseCategory,
    LicenseInfo,
    LicenseOutcome,
    LicenseRules,
    CompatibilityRule,
)


# --------------------------------------------------------------------------- #
# Hand-built rules (self-contained, mirrors the shape of license_rules.json)
# --------------------------------------------------------------------------- #
def _rules() -> LicenseRules:
    return LicenseRules(
        licenses={
            "MIT": LicenseInfo(category="permissive", base_risk="low"),
            "LGPL-2.1": LicenseInfo(category="copyleft-weak", base_risk="medium"),
            "GPL-3.0": LicenseInfo(category="copyleft-strong", base_risk="high"),
            "AGPL-3.0": LicenseInfo(category="copyleft-network", base_risk="high"),
            "": LicenseInfo(category="unknown", base_risk="medium"),
        },
        compatibility={
            "permissive": CompatibilityRule(distributed="ok", internal="ok"),
            "copyleft-weak": CompatibilityRule(distributed="review", internal="ok"),
            "copyleft-strong": CompatibilityRule(distributed="conflict", internal="review"),
            "copyleft-network": CompatibilityRule(distributed="conflict", internal="review"),
            "unknown": CompatibilityRule(distributed="review", internal="review"),
        },
    )


def _app(app_id: str, *, distributed: bool) -> Application:
    return Application(
        app_id=app_id,
        name=f"app-{app_id}",
        business_criticality="high",
        owner="team",
        environment="production",
        internet_facing=True,
        distributed=distributed,
    )


def _dep(app_id: str, license_id: str) -> Dependency:
    return Dependency(
        dependency_id="DEP-T",
        app_id=app_id,
        library_name="lib",
        version="1.0.0",
        license=license_id,
        dependency_type="direct",
        parent_dependency_id="",
        last_updated=date(2025, 1, 1),
        ecosystem="pypi",
        usage_signal="not_referenced",
    )


# --------------------------------------------------------------------------- #
# Category lookup
# --------------------------------------------------------------------------- #
def test_category_of_known_and_unknown() -> None:
    engine = LicenseEngine(_rules(), [])
    assert engine.category_of("GPL-3.0") is LicenseCategory.copyleft_strong
    assert engine.category_of("MIT") is LicenseCategory.permissive
    # unrecognised id falls back to the unknown category (via "")
    assert engine.category_of("NOPE-1.0") is LicenseCategory.unknown
    assert engine.category_of("") is LicenseCategory.unknown


# --------------------------------------------------------------------------- #
# Compatibility matrix — both distribution contexts
# --------------------------------------------------------------------------- #
def test_strong_copyleft_conflicts_only_when_distributed() -> None:
    engine = LicenseEngine(_rules(), [])
    assert engine.outcome_for("GPL-3.0", distributed=True) is LicenseOutcome.conflict
    assert engine.outcome_for("GPL-3.0", distributed=False) is LicenseOutcome.review


def test_network_copyleft_conflicts_when_distributed() -> None:
    engine = LicenseEngine(_rules(), [])
    assert engine.outcome_for("AGPL-3.0", distributed=True) is LicenseOutcome.conflict
    assert engine.outcome_for("AGPL-3.0", distributed=False) is LicenseOutcome.review


def test_weak_copyleft_is_review_when_distributed_ok_internally() -> None:
    engine = LicenseEngine(_rules(), [])
    assert engine.outcome_for("LGPL-2.1", distributed=True) is LicenseOutcome.review
    assert engine.outcome_for("LGPL-2.1", distributed=False) is LicenseOutcome.ok


def test_permissive_is_always_ok() -> None:
    engine = LicenseEngine(_rules(), [])
    assert engine.outcome_for("MIT", distributed=True) is LicenseOutcome.ok
    assert engine.outcome_for("MIT", distributed=False) is LicenseOutcome.ok


def test_unknown_license_is_review_both_ways() -> None:
    engine = LicenseEngine(_rules(), [])
    assert engine.outcome_for("", distributed=True) is LicenseOutcome.review
    assert engine.outcome_for("", distributed=False) is LicenseOutcome.review


# --------------------------------------------------------------------------- #
# App-aware dependency resolution — the distribution context comes from the app
# --------------------------------------------------------------------------- #
def test_outcome_for_dependency_uses_app_distributed_flag() -> None:
    apps = [_app("APP-DIST", distributed=True), _app("APP-INT", distributed=False)]
    engine = LicenseEngine(_rules(), apps)

    dist = engine.outcome_for_dependency(_dep("APP-DIST", "GPL-3.0"))
    internal = engine.outcome_for_dependency(_dep("APP-INT", "GPL-3.0"))

    assert dist is LicenseOutcome.conflict
    assert is_conflict(dist) is True
    assert internal is LicenseOutcome.review
    assert is_conflict(internal) is False


# --------------------------------------------------------------------------- #
# Free-function shortcut + integration with the real rules file
# --------------------------------------------------------------------------- #
def test_resolve_outcome_free_function() -> None:
    rules = _rules()
    assert resolve_outcome(rules, "GPL-3.0", True) is LicenseOutcome.conflict


def test_real_license_rules_file_resolves() -> None:
    rules = load_license_rules("data")
    # Sanity against the shipped rules: AGPL distributed conflicts, MIT is ok.
    assert rules.resolve("AGPL-3.0", True) is LicenseOutcome.conflict
    assert rules.resolve("MIT", True) is LicenseOutcome.ok
