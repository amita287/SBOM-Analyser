"""Inherited-vulnerability analysis via the graph (Phase 4).

A dependency that is *clean of any direct CVE itself* but sits on a path to a
vulnerable descendant is ``transitive_vulnerable`` (Section 5.1 / 6.2). This
module walks the structural graph to find those nodes and, for each, the nearest
vulnerable descendant that feeds the decayed transitive score (Section 7.1).

Detection stays decoupled: the "who is directly vulnerable?" question is answered
in :mod:`analysis.vulnerabilities` and handed in here as a ``base_vuln`` map. A
dep counts as directly vulnerable exactly when its ``base_vuln > 0`` — the same
definition the generator uses — so the two agree by construction.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

import networkx as nx

from sbom_analyzer.graph.builder import NODE_KIND_DEP


@dataclass(frozen=True)
class TransitiveExposure:
    """A clean dep's inherited exposure to a vulnerable descendant."""

    dependency_id: str
    nearest_vulnerable_id: str
    hop_distance: int
    nearest_base_vuln: float


def dependency_nodes(graph: nx.DiGraph) -> list[str]:
    """All dependency-occurrence nodes (excludes application roots)."""
    return [
        node
        for node, data in graph.nodes(data=True)
        if data.get("kind") == NODE_KIND_DEP
    ]


def nearest_vulnerable_descendant(
    graph: nx.DiGraph, node_id: str, base_vuln_by_dep: Mapping[str, float]
) -> tuple[str | None, int, float]:
    """Nearest vulnerable descendant of ``node_id``.

    "Nearest" is fewest hops; among descendants tied at that hop distance the one
    with the highest ``base_vuln`` wins (ties broken by id for determinism) — the
    same choice the generator makes, and the value that feeds
    :func:`scoring.risk.transitive_component`.
    """
    lengths = nx.single_source_shortest_path_length(graph, node_id)
    hits = [
        (dep, hop)
        for dep, hop in lengths.items()
        if hop > 0 and base_vuln_by_dep.get(dep, 0.0) > 0.0
    ]
    if not hits:
        return None, 0, 0.0
    nearest_hop = min(hop for _dep, hop in hits)
    best = max(
        (dep for dep, hop in hits if hop == nearest_hop),
        key=lambda dep: (base_vuln_by_dep[dep], dep),
    )
    return best, nearest_hop, base_vuln_by_dep[best]


def classify(
    graph: nx.DiGraph, base_vuln_by_dep: Mapping[str, float]
) -> dict[str, TransitiveExposure]:
    """Every ``transitive_vulnerable`` dependency, keyed by id.

    A node qualifies when it is *not itself* directly vulnerable
    (``base_vuln == 0``) yet has at least one vulnerable descendant. Directly
    vulnerable nodes are excluded: they *are* the vulnerability, not on a path
    to one.
    """
    result: dict[str, TransitiveExposure] = {}
    for node in dependency_nodes(graph):
        if base_vuln_by_dep.get(node, 0.0) > 0.0:
            continue  # directly vulnerable — not a transitive classification
        dep_id, hop, base = nearest_vulnerable_descendant(
            graph, node, base_vuln_by_dep
        )
        if dep_id is not None:
            result[node] = TransitiveExposure(node, dep_id, hop, base)
    return result


def transitive_vulnerable_ids(
    graph: nx.DiGraph, base_vuln_by_dep: Mapping[str, float]
) -> set[str]:
    """Just the set of transitively-vulnerable dependency ids."""
    return set(classify(graph, base_vuln_by_dep))
