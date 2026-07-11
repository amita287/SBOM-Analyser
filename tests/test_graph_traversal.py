"""Graph traversal tests — guards the 100% transitive metric (Phase 3).

Reserved — real tests land with the traversal code (hand-built App->A->B->C
chain + diamond fixture, per Section 6.3).
"""

import pytest

pytestmark = pytest.mark.skip(reason="Phase 3 — graph traversal not implemented yet")


def test_placeholder() -> None:
    pass
