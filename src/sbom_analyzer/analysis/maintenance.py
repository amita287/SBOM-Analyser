"""Maintenance / staleness check (Phase 4).

A dependency is ``unmaintained`` when its ``last_updated`` is more than two years
before the frozen reference date. Age, the stale threshold, and the penalty all
come from :mod:`sbom_analyzer.scoring.risk` — the single source of truth — so the
analyzer and the generator's label computation cannot drift.

The reference date is the same frozen ``TODAY`` the generator used; using it
(never ``datetime.now()``) is what makes the analyzer's staleness verdict line
up exactly with the ground-truth ``unmaintained`` labels.
"""

from __future__ import annotations

from datetime import date

from sbom_analyzer.models.entities import Dependency
from sbom_analyzer.models.findings import MaintenanceStatus
from sbom_analyzer.scoring.risk import (
    STALE_THRESHOLD_YEARS,
    age_in_years,
    maintenance_penalty_for,
)

# Frozen reference "now" — MUST equal the generator's TODAY (CLAUDE.md).
TODAY = date(2026, 4, 15)


def is_unmaintained(last_updated: date, today: date = TODAY) -> bool:
    """True iff older than the stale threshold (strictly > 2 years)."""
    return age_in_years(last_updated, today) > STALE_THRESHOLD_YEARS


def assess(last_updated: date, today: date = TODAY) -> MaintenanceStatus:
    """Full maintenance breakdown for one ``last_updated`` date."""
    age = age_in_years(last_updated, today)
    return MaintenanceStatus(
        last_updated=last_updated,
        age_years=age,
        is_stale=age > STALE_THRESHOLD_YEARS,
        maintenance_penalty=maintenance_penalty_for(last_updated, today),
    )


def assess_dependency(dep: Dependency, today: date = TODAY) -> MaintenanceStatus:
    """Convenience wrapper over :func:`assess` for a dependency row."""
    return assess(dep.last_updated, today)
