"""Build a ``networkx.DiGraph`` from dependency rows (Phase 3, Section 6.1).

The graph is purely *structural* — nodes and edges, with row fields carried as
node attributes. It knows nothing about vulnerabilities, licenses, or scores;
those are detection concerns answered independently in Phase 4 and threaded into
traversal as an explicit set of vulnerable node ids. Keeping the builder free of
detection is what lets the eval measure the analyzer, not a shared shortcut.

Shape (Section 6.1):
- one node per application (``app_id``) and one per dependency occurrence
  (``dependency_id``); every node carries a ``kind`` attribute;
- ``app_id -> dependency_id`` edges for direct deps, ``parent -> child`` edges
  for transitive deps. Edge direction means "depends on / pulls in".
- The result is a forest per app, joined at the app nodes, held as one DiGraph.
"""

from __future__ import annotations

from typing import Iterable

import networkx as nx

from sbom_analyzer.models.entities import Application, Dependency

NODE_KIND_APP = "application"
NODE_KIND_DEP = "dependency"


def build_graph(
    applications: Iterable[Application],
    dependencies: Iterable[Dependency],
) -> nx.DiGraph:
    """Assemble the dependency DiGraph.

    Raises ``ValueError`` on a dangling edge (a parent/app that is not a known
    node) or a cycle — the graph must be a DAG for traversal to terminate.
    """
    graph = nx.DiGraph()

    for app in applications:
        graph.add_node(app.app_id, kind=NODE_KIND_APP, **app.model_dump())

    # Nodes first, edges second: a transitive child may be listed before its
    # parent in the file, so every node must exist before any edge is drawn.
    deps = list(dependencies)
    for dep in deps:
        graph.add_node(dep.dependency_id, kind=NODE_KIND_DEP, **dep.model_dump())

    for dep in deps:
        parent = dep.parent_dependency_id or dep.app_id
        if parent not in graph:
            raise ValueError(
                f"{dep.dependency_id}: parent {parent!r} is not a known node "
                f"(app or dependency). Dangling edge — data is inconsistent."
            )
        graph.add_edge(parent, dep.dependency_id)

    if not nx.is_directed_acyclic_graph(graph):
        cycle = nx.find_cycle(graph)
        raise ValueError(f"dependency graph is not a DAG; cycle found: {cycle}")

    return graph
