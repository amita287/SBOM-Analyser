"""Provider-agnostic LLM client (Section 8.1).

Phase 0 stub: only the disabled path (`LLM_PROVIDER=none`) is wired. In that
mode `complete_json` returns ``None`` so every reasoner falls back to its
deterministic result — the LLM is an enhancement, never a dependency. Real
OpenAI-compatible and Anthropic providers arrive in Phase 6.
"""

from __future__ import annotations

import logging
from typing import Any

from ..config import LLMProvider, Settings, get_settings

logger = logging.getLogger(__name__)


class LLMClient:
    """One method: ``complete_json(system, user, schema)``.

    Every call is meant to run at ``temperature=0`` with JSON output validated
    against a Pydantic schema. On any error or when disabled, callers must fall
    back deterministically — a failed LLM call never crashes the analysis.
    """

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()

    @property
    def enabled(self) -> bool:
        return self.settings.llm_provider is not LLMProvider.none

    def complete_json(
        self,
        system: str,
        user: str,
        schema: type | None = None,
    ) -> dict[str, Any] | None:
        """Return a JSON object for the prompt, or ``None`` to signal fallback.

        Args:
            system: system prompt.
            user: user prompt (fully grounded facts).
            schema: optional Pydantic model type to validate/parse against.

        Returns:
            ``None`` when ``LLM_PROVIDER=none`` (deterministic fallback path).
        """
        if not self.enabled:
            logger.debug("LLM disabled (provider=none); returning None fallback.")
            return None

        # Phase 6 will dispatch to the OpenAI-compatible / Anthropic backends.
        raise NotImplementedError(
            f"LLM provider {self.settings.llm_provider.value!r} is not implemented "
            "yet (Phase 6). Set LLM_PROVIDER=none to use deterministic fallbacks."
        )
