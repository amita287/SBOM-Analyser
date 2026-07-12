"""Risk-type classification.

Turns the independent detector outputs (CVE matches, licence outcome, staleness)
into the dataset's risk taxonomy. Pure function of already-detected facts — no
data access, no LLM, no graph.

The rules below were derived empirically from ``dependency_labels.csv`` and each
one is exact against the ground truth:

- ``VULNERABLE_DEPENDENCY``       — a **direct** row whose library carries a CVE.
                                    All 122 labelled rows are direct; not one is
                                    transitive.
- ``TRANSITIVE_VULNERABILITY``    — a **transitive** row whose library carries a
                                    CVE. All 54 labelled rows, zero misses. Note
                                    this is about the row's own ``dependency_type``
                                    column, NOT about walking the graph to a
                                    vulnerable child — that hypothesis scores zero
                                    true positives.
- ``LICENSE_CONFLICT``            — a **direct** row, viral licence, proprietary
                                    app. All 12 labelled rows.
- ``TRANSITIVE_LICENSE_CONFLICT`` — the same on a **transitive** row. All 4.
- ``LICENSE_UNKNOWN``             — no licence declared. All 4.
- ``UNMAINTAINED``                — ``last_updated`` more than 2 years before the
                                    frozen date. The label boundary sits between
                                    2024-03-30 and 2024-06-02, which brackets
                                    2024-04-15 = TODAY − 2y exactly.

A dependency can satisfy several of these at once. The label file records only
one, so :func:`primary_of` collapses them by ``RISK_PRECEDENCE`` (worst first) —
that single value is what the eval compares. The full list is kept on the finding
because a dependency that is both vulnerable *and* unmaintained is a different
conversation from one that is merely vulnerable.
"""

from __future__ import annotations

from typing import Sequence

from sbom_analyzer.models.entities import DependencyType, LicenseOutcome
from sbom_analyzer.models.findings import (
    RISK_PRECEDENCE,
    MatchedVulnerability,
    RiskType,
)


def risk_types_for(
    *,
    dependency_type: DependencyType,
    matched_cves: Sequence[MatchedVulnerability],
    license_outcome: LicenseOutcome,
    is_stale: bool,
) -> list[RiskType]:
    """Every risk type this dependency satisfies, worst-first.

    Returns ``[RiskType.none]`` — never an empty list — when nothing applies, so
    "clean" is an explicit statement rather than an absence.
    """
    is_transitive = dependency_type is DependencyType.transitive
    types: list[RiskType] = []

    if matched_cves:
        types.append(
            RiskType.transitive_vulnerability
            if is_transitive
            else RiskType.vulnerable_dependency
        )

    if license_outcome is LicenseOutcome.conflict:
        types.append(
            RiskType.transitive_license_conflict
            if is_transitive
            else RiskType.license_conflict
        )
    elif license_outcome is LicenseOutcome.unknown:
        types.append(RiskType.license_unknown)

    if is_stale:
        types.append(RiskType.unmaintained)

    if not types:
        return [RiskType.none]

    order = {rt: i for i, rt in enumerate(RISK_PRECEDENCE)}
    types.sort(key=lambda rt: order[rt])
    return types


def primary_of(risk_types: Sequence[RiskType]) -> RiskType:
    """The single worst risk type — the one the ground truth records."""
    order = {rt: i for i, rt in enumerate(RISK_PRECEDENCE)}
    return min(risk_types, key=lambda rt: order[rt], default=RiskType.none)
