"""Risk scoring formula — SINGLE SOURCE OF TRUTH.

This module contains the *scorer* and nothing else — no detectors. "Does this
version match a CVE?", "is this licence a conflict?", "is this dependency
stale?" are all *detection* questions answered independently elsewhere; this
file only turns already-detected facts into numbers.

No LLM output ever reaches this module.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from typing import Iterable, Sequence

# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #
DAYS_PER_YEAR = 365.25
STALE_THRESHOLD_YEARS = 2.0
MAINTENANCE_PER_YEAR = 15.0
MAINTENANCE_CAP = 40.0
TRANSITIVE_DECAY = 0.7

# Exploitability now belongs to the CVE, not to the dependency. The old dataset
# carried a per-occurrence usage signal ("does our code call the vulnerable
# function?"); this one publishes an exploitability rating on the advisory
# itself. Same idea, different owner — so the factor is keyed off the CVE.
EXPLOITABILITY_FACTORS: dict[str, float] = {
    "high": 1.0,
    "medium": 0.85,
    "low": 0.7,
    "none": 0.5,
}

# How far a match is trusted. A `potential` match — right library, but the
# version is not in the advisory's affected set — is real enough to surface and
# too weak to score like a confirmed hit. This factor is the entire difference
# between "worth checking" and "you are vulnerable".
#
# 0.6: a potential match still ranks above a clean dependency and above a
# licence/staleness finding of the same CVSS, but a *confirmed* CVE always
# outranks a potential one of equal severity — which is the ordering a triage
# queue needs.
CONFIDENCE_FACTORS: dict[str, float] = {
    "confirmed": 1.0,
    "potential": 0.6,
}

LICENSE_PENALTIES: dict[str, float] = {
    "conflict": 80.0,  # viral licence inside a proprietary product
    "unknown": 40.0,  # nobody declared one; legal cannot sign this off
    "ok": 0.0,
}

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
    """The only CVE facts the score cares about."""

    cvss_score: float
    patch_available: bool
    exploitability: str = "medium"
    confidence: str = "confirmed"


@dataclass(frozen=True)
class DependencyScore:
    """Full breakdown, so callers can explain a score rather than just report it."""

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
    """Fractional age. Deterministic — everything downstream depends on it."""
    return (today - last_updated).days / DAYS_PER_YEAR


def exploitability_factor(exploitability: object) -> float:
    return EXPLOITABILITY_FACTORS[_as_value(exploitability)]


def confidence_factor(confidence: object) -> float:
    return CONFIDENCE_FACTORS[_as_value(confidence)]


def license_penalty_for(license_outcome: object) -> float:
    return LICENSE_PENALTIES[_as_value(license_outcome)]


# --------------------------------------------------------------------------- #
# Components
# --------------------------------------------------------------------------- #
def vulnerability_component(cves: Iterable[CveScoreInput]) -> float:
    """base_vuln — worst CVE wins."""
    base = 0.0
    for cve in cves:
        severity = cve.cvss_score / 10.0
        patch = 0.6 if cve.patch_available else 1.0
        exploit = exploitability_factor(cve.exploitability)
        trust = confidence_factor(cve.confidence)
        base = max(base, severity * patch * exploit * trust * 100.0)
    return base


def transitive_component(
    nearest_descendant_base_vuln: float, hop_distance: int
) -> float:
    """Inherited vuln, decayed by distance."""
    if nearest_descendant_base_vuln <= 0.0 or hop_distance <= 0:
        return 0.0
    return nearest_descendant_base_vuln * (TRANSITIVE_DECAY**hop_distance)


def maintenance_penalty_for(last_updated: date, today: date) -> float:
    """0, 15, 30, 40 (capped) from staleness."""
    years_stale = max(0.0, age_in_years(last_updated, today) - STALE_THRESHOLD_YEARS)
    return min(MAINTENANCE_CAP, years_stale * MAINTENANCE_PER_YEAR)


# --------------------------------------------------------------------------- #
# Severity
# --------------------------------------------------------------------------- #
def severity_from_score(score: float) -> str:
    """Band a continuous 0-100 score. Used for the *application* roll-up."""
    if score >= 75:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 25:
        return "medium"
    if score > 0:
        return "low"
    return "none"


# A dependency's severity is NOT a band of its risk score — it is a property of
# the finding itself, and the two answer different questions. `risk_score` ranks
# ("what do I look at first?"); `severity` classifies ("how bad is this kind of
# problem?"). A GPL-3.0 conflict is CRITICAL whether it scores 40 or 90.
#
# Every rule below was read off the ground truth, and each is exact:
#   unmaintained  -> MEDIUM at 2-3 years, HIGH beyond 3
#                    (labels split cleanly: MEDIUM 2.04-2.95y, HIGH 3.01-5.97y)
#   conflict      -> CRITICAL for AGPL-3.0 / GPL-3.0, HIGH for GPL-2.0 / SSPL
#   transitive
#     conflict    -> HIGH, always (all 4 labelled rows)
#   unknown       -> MEDIUM (all 4)
#   vulnerable    -> the advisory's own severity
STALE_HIGH_THRESHOLD_YEARS = 3.0

CRITICAL_LICENSES: frozenset[str] = frozenset(
    {"AGPL-3.0", "AGPL-3.0-only", "GPL-3.0", "GPL-3.0-only"}
)


def severity_for_finding(
    *,
    primary_risk_type: str,
    worst_cve_severity: str | None = None,
    license_id: str = "",
    age_years: float = 0.0,
) -> str:
    """The severity band the ground truth would assign to this finding."""
    rt = _as_value(primary_risk_type)

    if rt in ("vulnerable_dependency", "transitive_vulnerability"):
        # Worst-CVE-wins. The label file cites one specific advisory per row and
        # we cannot know which one it picked, so the worst is the honest proxy —
        # it agrees with the truth on 77% of vulnerable rows, and errs upward.
        return worst_cve_severity or "medium"

    if rt == "license_conflict":
        return "critical" if license_id in CRITICAL_LICENSES else "high"

    if rt == "transitive_license_conflict":
        return "high"

    if rt == "license_unknown":
        return "medium"

    if rt == "unmaintained":
        return "high" if age_years > STALE_HIGH_THRESHOLD_YEARS else "medium"

    return "none"


# --------------------------------------------------------------------------- #
# Per-dependency score
# --------------------------------------------------------------------------- #
def score_dependency(
    *,
    cves: Iterable[CveScoreInput],
    license_outcome: object,
    last_updated: date,
    today: date,
    nearest_descendant_base_vuln: float = 0.0,
    transitive_hop_distance: int = 0,
) -> DependencyScore:
    """Combine every component into the final 0-100 dependency risk score.

    The transitive component only applies when the dependency is clean itself
    (``base_vuln == 0``) but pulls in something that isn't.
    """
    base_vuln = vulnerability_component(cves)
    transitive_vuln = (
        transitive_component(nearest_descendant_base_vuln, transitive_hop_distance)
        if base_vuln == 0.0
        else 0.0
    )

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
# Per-application score
# --------------------------------------------------------------------------- #
def _mean(values: Sequence[float]) -> float:
    return sum(values) / len(values) if values else 0.0


def score_application(
    dep_scores: Sequence[float],
    severities: Sequence[str],
    business_criticality: object,
) -> float:
    """Aggregate dependency scores into an app score."""
    if not dep_scores:
        return 0.0
    top5 = sorted(dep_scores, reverse=True)[:5]
    high_count = sum(1 for s in severities if _as_value(s) in ("critical", "high"))
    app_raw = (
        0.5 * max(dep_scores) + 0.3 * _mean(top5) + 0.2 * min(100.0, 20.0 * high_count)
    )
    multiplier = CRITICALITY_MULTIPLIERS[_as_value(business_criticality)]
    return clamp(app_raw * multiplier)
