"""Load and validate the five data files (Phase 2).

Stub — implemented in Phase 2. Loaders read data/ and validate every row
against the Section 4 schemas in ``sbom_analyzer.models``, failing loudly on
bad rows. The ground-truth ``dependency_labels.csv`` is loaded ONLY by the
eval harness, never by the analyzer.
"""

from __future__ import annotations
