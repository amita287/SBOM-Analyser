"""Graph traversal — the 100%-transitive-resolution metric lives here (Phase 3).

Section 6.2. Three functions, all pure over the structural graph plus an
explicit set of vulnerable node ids (supplied by the Phase 4 vulnerability
detector — traversal never decides *what* is vulnerable, only *what reaches*
it):

- :func:`descendants_of` — everything transitively below a node.
- :func:`paths_to_vulnerable` — every simple path from an app to each reachable
  vulnerable dependency. This is the attack-chain data the report and LLM
  narrative consume, and the set the 100% metric is scored against.
- :func:`is_on_path_to_vulnerable` — does a node have a vulnerable *descendant*?
  Drives the ``transitive_vulnerable`` classification.

Results are sorted so callers get deterministic output.
"""

from __future__ import annotations

from typing import Collection

import networkx as nx


def _as_set(vulnerable_ids: Collection[str]) -> set[str]:
    return vulnerable_ids if isinstance(vulnerable_ids, (set, frozenset)) else set(
        vulnerable_ids
    )


def descendants_of(graph: nx.DiGraph, node_id: str) -> set[str]:
    """All transitive dependencies below ``node_id`` (excludes the node itself)."""
    return nx.descendants(graph, node_id)


def is_on_path_to_vulnerable(
    graph: nx.DiGraph, node_id: str, vulnerable_ids: Collection[str]
) -> bool:
    """True iff some *descendant* of ``node_id`` is vulnerable.

    Strictly descendants: a node that is itself vulnerable but has no vulnerable
    thing beneath it is *not* on a path to a vulnerability — it *is* the
    vulnerability. That distinction is exactly what separates the
    ``transitive_vulnerable`` class from the directly ``vulnerable`` class.
    """
    vuln = _as_set(vulnerable_ids)
    if not vuln:
        return False
    return any(d in vuln for d in nx.descendants(graph, node_id))


def paths_to_vulnerable(
    graph: nx.DiGraph, app_id: str, vulnerable_ids: Collection[str]
) -> list[list[str]]:
    """Every simple path from ``app_id`` to each reachable vulnerable node.

    For a diamond (``A→B→D``, ``A→C→D`` with ``D`` vulnerable) both arms are
    returned as distinct paths. Paths are sorted for determinism.
    """
    vuln = _as_set(vulnerable_ids)
    if not vuln:
        return []
    targets = sorted(vuln & nx.descendants(graph, app_id))
    paths: list[list[str]] = []
    for target in targets:
        paths.extend(nx.all_simple_paths(graph, app_id, target))
    paths.sort()
    return paths
