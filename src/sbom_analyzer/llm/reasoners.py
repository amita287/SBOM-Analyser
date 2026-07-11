"""LLM reasoners with deterministic fallbacks (Phase 6, Section 8).

Stub — implemented in Phase 6:
  A. exploitability adjudication   B. false-positive adjudication
  C. attack-chain narrative        D. remediation playbook

Every reasoner is temperature=0, JSON, Pydantic-validated, and falls back to a
deterministic result on any error or schema-validation failure.
"""

from __future__ import annotations
