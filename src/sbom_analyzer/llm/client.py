"""Provider-agnostic LLM client (Phase 6, Section 8.1).

One method matters: :meth:`LLMClient.complete_json`. It returns a parsed JSON
object, or ``None`` — and ``None`` is the *only* failure signal. A missing SDK, a
bad API key, a network timeout, a refusal, malformed JSON, a schema violation:
all collapse to ``None`` so the caller falls back to its deterministic result.
**A failed LLM call must never crash the analysis or corrupt a metric.**

Determinism, per provider
-------------------------
The brief says "temperature=0". That parameter no longer exists on current
Anthropic models — ``temperature`` / ``top_p`` / ``top_k`` were removed on Opus
4.8/4.7 and Sonnet 5 and now return a **400**. So we honour the *intent*
(non-sampled, reproducible output) the way each API actually expresses it:

- **anthropic** — send no sampling parameters at all, leave thinking off, and
  constrain the reply with a JSON schema (``output_config.format``), which is a
  strictly stronger guarantee than "JSON mode": the shape cannot drift.
- **openai** (and any OpenAI-compatible endpoint — Ollama, vLLM, Together) —
  ``temperature=0`` plus ``response_format={"type": "json_object"}``, both still
  supported there.

Either way the reply is validated against a Pydantic model before a caller sees
it (:meth:`complete_model`).
"""

from __future__ import annotations

import json
import logging
from typing import Any, TypeVar

from pydantic import BaseModel, ValidationError

from ..config import LLMProvider, Settings, get_settings

logger = logging.getLogger(__name__)

T = TypeVar("T", bound=BaseModel)

# Anthropic default. Overridden by LLM_MODEL.
DEFAULT_ANTHROPIC_MODEL = "claude-opus-4-8"
DEFAULT_OPENAI_BASE_URL = "https://api.openai.com/v1"

OPENAI_TEMPERATURE = 0.0  # accepted on OpenAI-compatible APIs; rejected by Anthropic
DEFAULT_MAX_TOKENS = 1024
DEFAULT_TIMEOUT = 30.0

# JSON-schema keywords structured outputs does not accept. Pydantic emits these
# from `Field(ge=..., le=...)`; we strip them from the wire schema and let
# Pydantic enforce them client-side on the way back in.
_UNSUPPORTED_SCHEMA_KEYS = (
    "minimum",
    "maximum",
    "exclusiveMinimum",
    "exclusiveMaximum",
    "multipleOf",
    "minLength",
    "maxLength",
    "minItems",
    "maxItems",
)


def strict_json_schema(model_cls: type[BaseModel]) -> dict[str, Any]:
    """Pydantic model → a JSON schema the structured-outputs API will accept."""
    schema = model_cls.model_json_schema()
    _harden(schema)
    return schema


def _harden(node: Any) -> None:
    """Recursively: forbid extra keys, require every property, drop unsupported."""
    if isinstance(node, dict):
        for key in _UNSUPPORTED_SCHEMA_KEYS:
            node.pop(key, None)
        if node.get("type") == "object":
            node["additionalProperties"] = False
            props = node.get("properties") or {}
            if props:
                node["required"] = list(props)
        for value in node.values():
            _harden(value)
    elif isinstance(node, list):
        for value in node:
            _harden(value)


def _extract_json(text: str) -> dict[str, Any] | None:
    """Parse a JSON object out of a model reply, tolerating ```json fences."""
    body = text.strip()
    if body.startswith("```"):
        body = body.split("\n", 1)[-1] if "\n" in body else ""
        body = body.rsplit("```", 1)[0]
    start, end = body.find("{"), body.rfind("}")
    if start == -1 or end <= start:
        return None
    try:
        parsed = json.loads(body[start : end + 1])
    except json.JSONDecodeError:
        return None
    return parsed if isinstance(parsed, dict) else None


class LLMClient:
    """Thin, provider-agnostic JSON completion client. Never raises.

    Tracks ``calls`` / ``failures`` so callers can report how often the LLM
    actually contributed. A silent degradation to fallbacks is correct behaviour
    but must never be *invisible* — an out-of-credit key or a dead endpoint
    should be reported, not quietly papered over.
    """

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()
        self._anthropic: Any = None  # lazily constructed
        self.calls = 0
        self.failures = 0
        self.last_error: str | None = None

    @property
    def enabled(self) -> bool:
        return self.settings.llm_enabled

    # -- public API ---------------------------------------------------------- #
    def _fail(self, reason: str) -> None:
        self.failures += 1
        self.last_error = reason
        logger.warning("%s — using deterministic fallback.", reason)

    def complete_json(
        self,
        system: str,
        user: str,
        schema: dict[str, Any] | None = None,
        *,
        max_tokens: int | None = None,
    ) -> dict[str, Any] | None:
        """Return a JSON object, or ``None`` to signal "use your fallback"."""
        if not self.enabled:
            logger.debug("LLM disabled (provider=none); deterministic fallback.")
            return None

        self.calls += 1
        budget = max_tokens or self.settings.llm_max_tokens or DEFAULT_MAX_TOKENS
        try:
            raw = self._raw_complete(system, user, schema, budget)
        except Exception as exc:  # noqa: BLE001 — the whole point: never propagate
            self._fail(f"LLM call failed ({self.settings.llm_provider.value}): {exc}")
            return None

        data = _extract_json(raw or "")
        if data is None:
            self._fail("LLM returned non-JSON output")
        return data

    def complete_model(
        self,
        system: str,
        user: str,
        model_cls: type[T],
        *,
        max_tokens: int | None = None,
    ) -> T | None:
        """Same, but validated into ``model_cls``. Schema violation → ``None``."""
        data = self.complete_json(
            system, user, strict_json_schema(model_cls), max_tokens=max_tokens
        )
        if data is None:
            return None
        try:
            return model_cls.model_validate(data)
        except ValidationError as exc:
            self._fail(f"LLM output failed {model_cls.__name__} validation: {exc}")
            return None

    # -- provider dispatch --------------------------------------------------- #
    def _raw_complete(
        self,
        system: str,
        user: str,
        schema: dict[str, Any] | None,
        max_tokens: int,
    ) -> str:
        provider = self.settings.llm_provider
        if provider is LLMProvider.anthropic:
            return self._complete_anthropic(system, user, schema, max_tokens)
        if provider is LLMProvider.openai:
            return self._complete_openai(system, user, max_tokens)
        raise RuntimeError(f"unsupported LLM provider: {provider!r}")

    def _complete_anthropic(
        self,
        system: str,
        user: str,
        schema: dict[str, Any] | None,
        max_tokens: int,
    ) -> str:
        # Imported lazily: `anthropic` is an optional extra, and the pipeline
        # must run without it. An ImportError here is caught by complete_json.
        import anthropic

        if self._anthropic is None:
            self._anthropic = anthropic.Anthropic(
                api_key=self.settings.llm_api_key or None,
                timeout=DEFAULT_TIMEOUT,
                max_retries=2,
            )

        kwargs: dict[str, Any] = {
            "model": self.settings.llm_model or DEFAULT_ANTHROPIC_MODEL,
            "max_tokens": max_tokens,
            "system": system,
            "messages": [{"role": "user", "content": user}],
        }
        # No temperature/top_p/top_k — they 400 on current models. The schema is
        # what pins the output down.
        if schema is not None:
            kwargs["output_config"] = {
                "format": {"type": "json_schema", "schema": schema}
            }

        response = self._anthropic.messages.create(**kwargs)
        if getattr(response, "stop_reason", None) == "refusal":
            raise RuntimeError("model refused the request")
        return "".join(
            block.text for block in response.content if block.type == "text"
        )

    def _complete_openai(self, system: str, user: str, max_tokens: int) -> str:
        import httpx

        model = self.settings.llm_model
        if not model:
            raise RuntimeError("LLM_MODEL is required when LLM_PROVIDER=openai")
        base_url = (self.settings.llm_base_url or DEFAULT_OPENAI_BASE_URL).rstrip("/")

        response = httpx.post(
            f"{base_url}/chat/completions",
            headers={"Authorization": f"Bearer {self.settings.llm_api_key}"},
            json={
                "model": model,
                "temperature": OPENAI_TEMPERATURE,
                "max_tokens": max_tokens,
                "response_format": {"type": "json_object"},
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
            },
            timeout=DEFAULT_TIMEOUT,
        )

        # Surface the provider's own message. `raise_for_status()` alone reports
        # only "402 Payment Required", hiding the part that says *why* — which is
        # what turns a debuggable failure into a silent fallback.
        try:
            body = response.json()
        except ValueError:
            body = {}
        if isinstance(body, dict) and body.get("error"):
            err = body["error"]
            message = err.get("message") if isinstance(err, dict) else err
            raise RuntimeError(f"HTTP {response.status_code}: {message}")
        response.raise_for_status()

        return body["choices"][0]["message"]["content"]
