"""Risk scoring formula — SINGLE SOURCE OF TRUTH (Section 7).

This module is the ONLY code shared between the data generator and the
analyzer. It contains the *scorer* and nothing else — no detectors. "Does this
version match a CVE?", "is this license a conflict?", "what is the nearest
vulnerable descendant?" are all *detection* questions answered independently on
each side; this file only turns already-detected facts into numbers.

The formula is Section 7 of the implementation plan, transcribed literally.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from typing import Iterable, Sequence

# --------------------------------------------------------------------------- #
# Constants (Section 7)
# --------------------------------------------------------------------------- #
DAYS_PER_YEAR = 365.25
STALE_THRESHOLD_YEARS = 2.0
MAINTENANCE_PER_YEAR = 15.0
MAINTENANCE_CAP = 40.0
TRANSITIVE_DECAY = 0.7

# 7.2 exploitability factor
EXPLOITABILITY_FACTORS: dict[str, float] = {
    "calls_vulnerable_function": 1.0,
    "imports_only": 0.85,
    "not_referenced": 0.7,
}

# 7.1 license component
LICENSE_PENALTIES: dict[str, float] = {"conflict": 80.0, "review": 40.0, "ok": 0.0}

# 7.4 per-application criticality multiplier
CRITICALITY_MULTIPLIERS: dict[str, float] = {
    "critical": 1.2,
    "high": 1.1,
    "medium": 1.0,
    "low": 0.9,
}


# --------------------------------------------------------------------------- #
# Small value objects
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class CveScoreInput:
    """The only two CVE facts the score cares about."""

    cvss_score: float
    patch_available: bool


@dataclass(frozen=True)
class DependencyScore:
    """Full breakdown so callers can explain a score, not just report it."""

    risk_score: float
    severity: str
    base_vuln: float
    transitive_vuln: float
    license_penalty: float
    maintenance_penalty: float


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def _as_value(x: object) -> str:
    """Accept either a bare string or an Enum with a ``.value``."""
    return x.value if hasattr(x, "value") else str(x)


def clamp(x: float, lo: float = 0.0, hi: float = 100.0) -> float:
    return max(lo, min(hi, x))


def age_in_years(last_updated: date, today: date) -> float:
    """Fractional age. Deterministic; both sides must use this same function."""
    return (today - last_updated).days / DAYS_PER_YEAR


def exploitability_factor(usage_signal: object) -> float:
    """Section 7.2 — bounded, three buckets only."""
    return EXPLOITABILITY_FACTORS[_as_value(usage_signal)]


def license_penalty_for(license_outcome: object) -> float:
    return LICENSE_PENALTIES[_as_value(license_outcome)]


# --------------------------------------------------------------------------- #
# 7.1 components
# --------------------------------------------------------------------------- #
def vulnerability_component(
    cves: Iterable[CveScoreInput], usage_signal: object
) -> float:
    """base_vuln — worst CVE wins (Section 7.1)."""
    exploit = exploitability_factor(usage_signal)
    base = 0.0
    for cve in cves:
        sev = cve.cvss_score / 10.0
        patch = 0.6 if cve.patch_available else 1.0
        cve_score = sev * patch * exploit * 100.0
        base = max(base, cve_score)
    return base


def transitive_component(
    nearest_descendant_base_vuln: float, hop_distance: int
) -> float:
    """Inherited vuln, decayed by distance (Section 7.1)."""
    if nearest_descendant_base_vuln <= 0.0 or hop_distance <= 0:
        return 0.0
    return nearest_descendant_base_vuln * (TRANSITIVE_DECAY ** hop_distance)


def maintenance_penalty_for(last_updated: date, today: date) -> float:
    """0, 15, 30, 40 (capped) from staleness (Section 7.1)."""
    years_stale = max(0.0, age_in_years(last_updated, today) - STALE_THRESHOLD_YEARS)
    return min(MAINTENANCE_CAP, years_stale * MAINTENANCE_PER_YEAR)


# --------------------------------------------------------------------------- #
# 7.3 severity band
# --------------------------------------------------------------------------- #
def severity_from_score(score: float) -> str:
    if score >= 75:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 25:
        return "medium"
    if score > 0:
        return "low"
    return "none"


# --------------------------------------------------------------------------- #
# Per-dependency score (Section 7.1)
# --------------------------------------------------------------------------- #
def score_dependency(
    *,
    cves: Iterable[CveScoreInput],
    usage_signal: object,
    license_outcome: object,
    last_updated: date,
    today: date,
    nearest_descendant_base_vuln: float = 0.0,
    transitive_hop_distance: int = 0,
) -> DependencyScore:
    """Combine all components into the final 0-100 dependency risk score.

    The transitive component only applies when the dependency is *clean itself*
    (``base_vuln == 0``) but sits on a path to a vulnerable descendant — exactly
    the wording of Section 7.1.
    """
    base_vuln = vulnerability_component(cves, usage_signal)
    if base_vuln == 0.0:
        transitive_vuln = transitive_component(
            nearest_descendant_base_vuln, transitive_hop_distance
        )
    else:
        transitive_vuln = 0.0

    license_penalty = license_penalty_for(license_outcome)
    maintenance_penalty = maintenance_penalty_for(last_updated, today)

    dep_risk = clamp(
        max(base_vuln, transitive_vuln)
        + 0.5 * license_penalty
        + 0.5 * maintenance_penalty
    )
    return DependencyScore(
        risk_score=dep_risk,
        severity=severity_from_score(dep_risk),
        base_vuln=base_vuln,
        transitive_vuln=transitive_vuln,
        license_penalty=license_penalty,
        maintenance_penalty=maintenance_penalty,
    )


# --------------------------------------------------------------------------- #
# Per-application score (Section 7.4)
# --------------------------------------------------------------------------- #
def _mean(values: Sequence[float]) -> float:
    return sum(values) / len(values) if values else 0.0


def score_application(
    dep_scores: Sequence[float],
    severities: Sequence[str],
    business_criticality: object,
) -> float:
    """Aggregate dependency scores into an app score (Section 7.4)."""
    if not dep_scores:
        return 0.0
    top5 = sorted(dep_scores, reverse=True)[:5]
    high_count = sum(1 for s in severities if _as_value(s) in ("critical", "high"))
    app_raw = (
        0.5 * max(dep_scores)
        + 0.3 * _mean(top5)
        + 0.2 * min(100.0, 20.0 * high_count)
    )
    multiplier = CRITICALITY_MULTIPLIERS[_as_value(business_criticality)]
    return clamp(app_raw * multiplier)
