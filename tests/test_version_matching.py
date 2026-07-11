"""Vulnerability version-range matching tests (Phase 4).

Reserved — real tests land with the matcher. Version matching MUST use
``packaging.specifiers.SpecifierSet``, never raw string comparison.
"""

import pytest

pytestmark = pytest.mark.skip(reason="Phase 4 — vulnerability matcher not implemented yet")


def test_placeholder() -> None:
    pass
