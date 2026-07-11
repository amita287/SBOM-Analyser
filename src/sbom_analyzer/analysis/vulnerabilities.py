"""Version-range vulnerability matching (Phase 4).

Stub — implemented in Phase 4. Matching uses ``packaging.specifiers.SpecifierSet``
against ``vulnerability_db.json``; NEVER string comparison. Versions listed in a
CVE's ``backported_patch_builds`` are FP traps and must not be flagged.
"""

from __future__ import annotations
