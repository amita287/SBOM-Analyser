"""Risk scoring golden-value tests (Phase 5, Section 7.5).

Reserved — real tests land with the scoring formula (hand-computed golden
values feeding ``score_dependency`` / ``score_application``).
"""

import pytest

pytestmark = pytest.mark.skip(reason="Phase 5 — scoring formula not implemented yet")


def test_placeholder() -> None:
    pass
