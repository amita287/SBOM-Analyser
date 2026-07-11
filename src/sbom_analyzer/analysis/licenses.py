"""License rule engine (Phase 4, Section 4.4).

Resolves a dependency's SPDX id to a compatibility outcome — ``conflict`` /
``review`` / ``ok`` — in two deterministic steps (no LLM):

1. **category** — look the SPDX id up in ``license_rules.json`` (unknown ids and
   ``""`` fall back to the ``unknown`` category);
2. **matrix** — apply the compatibility rule for that category under the app's
   distribution context (``app.distributed``: shipping GPL to third parties is a
   conflict; the same license used only internally is a review).

The core lookup lives on :meth:`LicenseRules.resolve` (models package); this
module wraps it in a dependency/app-oriented API and exposes the intermediate
category for reporting and explanations.
"""

from __future__ import annotations

from typing import Iterable

from sbom_analyzer.models.entities import (
    Application,
    Dependency,
    LicenseCategory,
    LicenseOutcome,
    LicenseRules,
)


class LicenseEngine:
    """Deterministic license adjudicator, bound to a set of applications."""

    def __init__(
        self, rules: LicenseRules, applications: Iterable[Application]
    ) -> None:
        self._rules = rules
        self._distributed_by_app: dict[str, bool] = {
            app.app_id: app.distributed for app in applications
        }

    # -- step 1: category ---------------------------------------------------- #
    def category_of(self, license_id: str) -> LicenseCategory:
        """SPDX id → license category; unknown/blank fall back to ``unknown``."""
        info = self._rules.licenses.get(license_id) or self._rules.licenses.get("")
        return info.category if info else LicenseCategory.unknown

    # -- step 2: matrix ------------------------------------------------------ #
    def outcome_for(self, license_id: str, distributed: bool) -> LicenseOutcome:
        """SPDX id + distribution context → conflict/review/ok."""
        return self._rules.resolve(license_id, distributed)

    def outcome_for_dependency(self, dep: Dependency) -> LicenseOutcome:
        """Resolve using the dependency's owning app's ``distributed`` flag.

        A missing ``app_id`` raises ``KeyError`` — loud by design; a dependency
        that references an unknown app is a data error, not a silent ``ok``.
        """
        distributed = self._distributed_by_app[dep.app_id]
        return self._rules.resolve(dep.license, distributed)


def is_conflict(outcome: LicenseOutcome) -> bool:
    """True for a hard license conflict (drives the ``license_conflict`` type)."""
    return outcome is LicenseOutcome.conflict


def resolve_outcome(
    rules: LicenseRules, license_id: str, distributed: bool
) -> LicenseOutcome:
    """Free-function shortcut around :meth:`LicenseRules.resolve`."""
    return rules.resolve(license_id, distributed)
