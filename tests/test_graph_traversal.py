"""Graph traversal tests — guards the 100% transitive metric (Phase 3).

Hand-built fixtures per Section 6.3: a linear ``App→A→B→C(vuln)`` chain (built
through the real loader models + builder), and a diamond (``A→B→D``, ``A→C→D``)
built directly on a DiGraph, since one dependency *row* has a single parent and
cannot by itself give a node two parents — the diamond only arises when two
occurrences converge, which we model at the graph level.
"""

from __future__ import annotations

from datetime import date

import networkx as nx

from sbom_analyzer.graph.builder import (
    NODE_KIND_APP,
    NODE_KIND_DEP,
    build_graph,
)
from sbom_analyzer.graph.traversal import (
    descendants_of,
    is_on_path_to_vulnerable,
    paths_to_vulnerable,
)
from sbom_analyzer.models.entities import Application, Dependency


# --------------------------------------------------------------------------- #
# Fixture helpers
# --------------------------------------------------------------------------- #
def _app(app_id: str = "APP-T") -> Application:
    return Application(
        app_id=app_id,
        name="test-app",
        business_criticality="high",
        owner="team-test",
        environment="internal",
        internet_facing=False,
        distributed=False,
    )


def _dep(
    dep_id: str,
    app_id: str = "APP-T",
    *,
    parent: str = "",
    dtype: str = "direct",
) -> Dependency:
    return Dependency(
        dependency_id=dep_id,
        app_id=app_id,
        library_name=f"lib-{dep_id}",
        version="1.0.0",
        license="MIT",
        dependency_type=dtype,
        parent_dependency_id=parent,
        last_updated=date(2025, 1, 1),
        ecosystem="pypi",
        usage_signal="not_referenced",
    )


def _linear_chain() -> nx.DiGraph:
    """APP-T → A → B → C, with C the vulnerable leaf. Built via the builder."""
    app = _app()
    a = _dep("A", parent="", dtype="direct")
    b = _dep("B", parent="A", dtype="transitive")
    c = _dep("C", parent="B", dtype="transitive")
    return build_graph([app], [a, b, c])


def _diamond() -> nx.DiGraph:
    """APP-T → A → {B, C} → D, D vulnerable. Two occurrences converge on D."""
    g = nx.DiGraph()
    for edge in (("APP-T", "A"), ("A", "B"), ("A", "C"), ("B", "D"), ("C", "D")):
        g.add_edge(*edge)
    return g


# --------------------------------------------------------------------------- #
# Builder structure
# --------------------------------------------------------------------------- #
def test_builder_nodes_and_edges() -> None:
    g = _linear_chain()

    assert g.nodes["APP-T"]["kind"] == NODE_KIND_APP
    assert g.nodes["A"]["kind"] == NODE_KIND_DEP

    # direct dep hangs off the app; transitives hang off their parent dep.
    assert g.has_edge("APP-T", "A")
    assert g.has_edge("A", "B")
    assert g.has_edge("B", "C")
    assert not g.has_edge("APP-T", "B")


# --------------------------------------------------------------------------- #
# descendants_of
# --------------------------------------------------------------------------- #
def test_descendants_of_linear() -> None:
    g = _linear_chain()
    assert descendants_of(g, "A") == {"B", "C"}
    assert descendants_of(g, "C") == set()


def test_descendants_of_diamond() -> None:
    g = _diamond()
    assert descendants_of(g, "A") == {"B", "C", "D"}


# --------------------------------------------------------------------------- #
# paths_to_vulnerable
# --------------------------------------------------------------------------- #
def test_paths_to_vulnerable_linear() -> None:
    g = _linear_chain()
    paths = paths_to_vulnerable(g, "APP-T", {"C"})
    assert paths == [["APP-T", "A", "B", "C"]]


def test_paths_to_vulnerable_finds_both_diamond_arms() -> None:
    g = _diamond()
    paths = paths_to_vulnerable(g, "APP-T", {"D"})

    assert len(paths) == 2
    assert ["APP-T", "A", "B", "D"] in paths
    assert ["APP-T", "A", "C", "D"] in paths


def test_paths_to_vulnerable_multiple_targets_union() -> None:
    # C is a vulnerable leaf AND D (in the diamond) — but here in the linear
    # chain mark both B and C vulnerable to show every target contributes.
    g = _linear_chain()
    paths = paths_to_vulnerable(g, "APP-T", {"B", "C"})
    assert paths == [
        ["APP-T", "A", "B"],
        ["APP-T", "A", "B", "C"],
    ]


def test_paths_to_vulnerable_none_when_nothing_vulnerable() -> None:
    g = _linear_chain()
    assert paths_to_vulnerable(g, "APP-T", set()) == []
    assert paths_to_vulnerable(g, "APP-T", {"not-a-node"}) == []


# --------------------------------------------------------------------------- #
# is_on_path_to_vulnerable
# --------------------------------------------------------------------------- #
def test_is_on_path_identifies_intermediates_linear() -> None:
    g = _linear_chain()
    vuln = {"C"}
    # intermediates have a vulnerable descendant ...
    assert is_on_path_to_vulnerable(g, "A", vuln) is True
    assert is_on_path_to_vulnerable(g, "B", vuln) is True
    # ... the vulnerable leaf itself does not (it *is* the vuln, not on a path).
    assert is_on_path_to_vulnerable(g, "C", vuln) is False


def test_is_on_path_identifies_intermediates_diamond() -> None:
    g = _diamond()
    vuln = {"D"}
    assert is_on_path_to_vulnerable(g, "A", vuln) is True
    assert is_on_path_to_vulnerable(g, "B", vuln) is True
    assert is_on_path_to_vulnerable(g, "C", vuln) is True
    assert is_on_path_to_vulnerable(g, "D", vuln) is False


def test_is_on_path_false_without_vulnerable_set() -> None:
    g = _linear_chain()
    assert is_on_path_to_vulnerable(g, "A", set()) is False
