"""Build a ``networkx.DiGraph`` from the SBOM.

The graph is purely *structural* — nodes and edges, with row fields carried as
node attributes. It knows nothing about vulnerabilities, licences, or scores;
those are detection concerns answered independently and threaded in later.
Keeping the builder free of detection is what lets the eval measure the
analyzer, not a shared shortcut.

Shape
-----
Three kinds of node:

- ``application`` — one per app.
- ``dependency``  — one per SBOM row (the only nodes that are ever *scored*).
- ``external``    — a library named in a row's ``transitive_deps`` that has no
  SBOM row of its own.

Every dependency row hangs off its application. This dataset gives no parent
pointer for rows marked ``transitive`` — they are simply *labelled* transitive;
there is no column linking them to the direct dependency that pulled them in. So
rather than invent an edge that isn't in the data, every row attaches to its app
and the row's own ``dependency_type`` carries the direct/transitive fact.

The one real parent->child structure in the dataset is the ``transitive_deps``
column, and **its children are phantoms**: all 372 of them are absent from the
dependency table. They become ``external`` nodes — visible in the graph, never
scored, because the ground truth does not score them either.

Edge direction means "depends on / pulls in". The result is a forest per app,
joined at the app nodes, held as one DiGraph.
"""

from __future__ import annotations

from typing import Iterable

import networkx as nx

from sbom_analyzer.models.entities import Application, Dependency

NODE_KIND_APP = "application"
NODE_KIND_DEP = "dependency"
NODE_KIND_EXT = "external"


def external_node_id(app_id: str, library_name: str, version: str) -> str:
    """Stable id for a phantom transitive child.

    Scoped by app: the same library pulled into two applications is two distinct
    exposures, and collapsing them into one node would fuse two apps' subgraphs
    into a single component that no longer reflects the SBOM.
    """
    return f"EXT:{app_id}:{library_name}@{version}"


def build_graph(
    applications: Iterable[Application],
    dependencies: Iterable[Dependency],
) -> nx.DiGraph:
    """Assemble the dependency DiGraph.

    Raises ``ValueError`` on a dangling edge (a row whose app is unknown) or a
    cycle — the graph must be a DAG for traversal to terminate.
    """
    graph = nx.DiGraph()

    for app in applications:
        graph.add_node(app.app_id, kind=NODE_KIND_APP, **app.model_dump())

    deps = list(dependencies)

    # Nodes first, edges second — a row may reference an app listed after it.
    for dep in deps:
        data = dep.model_dump()
        # The children are edges, not a node attribute; keep them off the node so
        # the payload stays flat and JSON-serialisable for the API.
        data.pop("transitive_children", None)
        graph.add_node(dep.dependency_id, kind=NODE_KIND_DEP, **data)

    for dep in deps:
        if dep.app_id not in graph:
            raise ValueError(
                f"{dep.dependency_id}: application {dep.app_id!r} is not a known "
                f"node. Dangling edge — data is inconsistent."
            )
        graph.add_edge(dep.app_id, dep.dependency_id)

        for child in dep.transitive_children:
            child_id = external_node_id(dep.app_id, child.library_name, child.version)
            if child_id not in graph:
                graph.add_node(
                    child_id,
                    kind=NODE_KIND_EXT,
                    app_id=dep.app_id,
                    library_name=child.library_name,
                    version=child.version,
                )
            graph.add_edge(dep.dependency_id, child_id)

    if not nx.is_directed_acyclic_graph(graph):
        cycle = nx.find_cycle(graph)
        raise ValueError(f"dependency graph is not a DAG; cycle found: {cycle}")

    return graph
