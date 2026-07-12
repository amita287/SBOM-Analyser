"""Inherited-vulnerability analysis via the graph.

Two different things get called "transitive" in this project, and conflating them
is the easiest way to get the metrics wrong. They are NOT the same:

1. **The risk type** ``transitive_vulnerability``. In the supplied dataset this
   means "this SBOM row is itself marked ``dependency_type=transitive`` AND its
   own library carries a CVE" — a vulnerability that arrived transitively. It is
   decided by a column, not by walking the graph. That classification lives in
   :mod:`sbom_analyzer.analysis.classify`, and it is what the ground truth
   labels. (Verified: all 54 ``TRANSITIVE_VULNERABILITY`` rows are transitive-type
   rows carrying their own CVE; the "a child of mine is vulnerable" hypothesis
   scores *zero* true positives.)

2. **Graph exposure** — this module. A dependency that is clean itself but
   *pulls in* a vulnerable library through ``transitive_deps``. The dataset's
   labels never flag this, but it is a real exposure, and it is what the attack
   paths in the report are drawn from. It feeds the decayed ``transitive_vuln``
   score component and never a risk type — so it can enrich the report without
   moving a number the eval checks.
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
    """All scored SBOM-row nodes (excludes apps and phantom externals)."""
    return [
        node
        for node, data in graph.nodes(data=True)
        if data.get("kind") == NODE_KIND_DEP
    ]


def nearest_vulnerable_descendant(
    graph: nx.DiGraph, node_id: str, base_vuln_by_node: Mapping[str, float]
) -> tuple[str | None, int, float]:
    """Nearest vulnerable descendant of ``node_id``.

    "Nearest" is fewest hops; among descendants tied at that hop distance the one
    with the highest ``base_vuln`` wins (ties broken by id, for determinism).
    """
    lengths = nx.single_source_shortest_path_length(graph, node_id)
    hits = [
        (node, hop)
        for node, hop in lengths.items()
        if hop > 0 and base_vuln_by_node.get(node, 0.0) > 0.0
    ]
    if not hits:
        return None, 0, 0.0

    nearest_hop = min(hop for _n, hop in hits)
    best = max(
        (n for n, hop in hits if hop == nearest_hop),
        key=lambda n: (base_vuln_by_node[n], n),
    )
    return best, nearest_hop, base_vuln_by_node[best]


def classify(
    graph: nx.DiGraph, base_vuln_by_node: Mapping[str, float]
) -> dict[str, TransitiveExposure]:
    """Every dependency exposed to a vulnerable descendant, keyed by id.

    A node qualifies when it is *not itself* vulnerable (``base_vuln == 0``) yet
    reaches something that is. Directly vulnerable nodes are excluded: they *are*
    the vulnerability, not a path to one.
    """
    result: dict[str, TransitiveExposure] = {}
    for node in dependency_nodes(graph):
        if base_vuln_by_node.get(node, 0.0) > 0.0:
            continue
        target, hop, base = nearest_vulnerable_descendant(
            graph, node, base_vuln_by_node
        )
        if target is not None:
            result[node] = TransitiveExposure(node, target, hop, base)
    return result


def exposed_dependency_ids(
    graph: nx.DiGraph, base_vuln_by_node: Mapping[str, float]
) -> set[str]:
    """Just the set of graph-exposed dependency ids."""
    return set(classify(graph, base_vuln_by_node))
