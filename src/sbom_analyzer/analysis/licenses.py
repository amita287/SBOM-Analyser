"""Licence rule engine.

Resolves a dependency's licence to an outcome — ``conflict`` / ``unknown`` /
``ok`` — in two deterministic steps (no LLM):

1. **lookup** — find the licence in ``license_rules.json``. The SBOM and the rule
   book do not spell licences the same way (``GPL-3.0`` vs ``GPL-3.0-only``,
   ``UNKNOWN`` vs ``NOASSERTION``), so the lookup goes through an alias table.
   Left unmapped, every copyleft dependency silently misses its rule and no
   conflict is ever raised — the licence half of the product goes dark without a
   single error.

2. **context** — a *viral* licence is only a conflict when the application ships
   as a proprietary product. The same GPL library inside an internal-only tool is
   fine, and saying otherwise is a false positive with legal consequences.

A licence that is *declared but unrecognised* (the dataset carries
``Dual-MIT/Commercial``, which the rule book never mentions) is NOT "unknown".
Unknown means nobody declared one. Conflating the two would flag 66 healthy
dependencies.
"""

from __future__ import annotations

from typing import Iterable

from sbom_analyzer.models.entities import (
    Application,
    Dependency,
    LicenseOutcome,
    LicenseRule,
    LicenseRules,
)


class LicenseEngine:
    """Deterministic licence adjudicator, bound to a set of applications."""

    def __init__(
        self, rules: LicenseRules, applications: Iterable[Application]
    ) -> None:
        self._rules = rules
        self._distributed_by_app: dict[str, bool] = {
            app.app_id: app.distributed for app in applications
        }

    def rule_for(self, license_id: str) -> LicenseRule | None:
        """The rule-book entry for a licence as the SBOM spells it."""
        return self._rules.lookup(license_id)

    def is_viral(self, license_id: str) -> bool:
        rule = self.rule_for(license_id)
        return bool(rule and rule.viral)

    def outcome_for(self, license_id: str, *, distributed: bool) -> LicenseOutcome:
        return self._rules.resolve(license_id, distributed=distributed)

    def outcome_for_dependency(self, dep: Dependency) -> LicenseOutcome:
        """Resolve using the owning application's distribution context.

        An unknown ``app_id`` raises ``KeyError`` — loud by design. A dependency
        that references an application we have never heard of is a data error,
        not a silent ``ok``.
        """
        distributed = self._distributed_by_app[dep.app_id]
        return self._rules.resolve(dep.license, distributed=distributed)


def is_conflict(outcome: LicenseOutcome) -> bool:
    """True for a hard licence conflict."""
    return outcome is LicenseOutcome.conflict


def is_unknown(outcome: LicenseOutcome) -> bool:
    """True when no licence was declared at all."""
    return outcome is LicenseOutcome.unknown


def resolve_outcome(
    rules: LicenseRules, license_id: str, distributed: bool
) -> LicenseOutcome:
    """Free-function shortcut around :meth:`LicenseRules.resolve`."""
    return rules.resolve(license_id, distributed=distributed)
