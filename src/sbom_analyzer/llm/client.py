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
import time
import logging
from typing import Any, TypeVar

from pydantic import BaseModel, ValidationError

from ..config import LLMProvider, Settings, get_settings

logger = logging.getLogger(__name__)

T = TypeVar("T", bound=BaseModel)

# Anthropic default. Overridden by LLM_MODEL.
DEFAULT_ANTHROPIC_MODEL = "claude-opus-4-8"
DEFAULT_OPENAI_BASE_URL = "https://api.openai.com/v1"
# Gemini speaks OpenAI's wire format at this host, so it reuses the same request
# shape rather than pulling in the google-genai SDK for four fields.
DEFAULT_GEMINI_BASE_URL = "https://generativelanguage.googleapis.com/v1beta/openai"

# A 429 means "wait", not "give up". Free-tier keys rate-limit hard, so a single
# attempt throws away answers the provider would have given. Bounded on purpose:
# when the daily quota is genuinely spent, retrying forever just hangs the run.
RATE_LIMIT_RETRIES = 3
RATE_LIMIT_BACKOFF = 2.0  # seconds; doubles each attempt


def _is_rate_limited(exc: Exception) -> bool:
    """Every provider spells 429 differently; all of them say it somewhere."""
    text = str(exc).lower()
    return "429" in text or "rate limit" in text or "quota" in text


def _gemini_base_url(configured: str) -> str:
    """Resolve LLM_BASE_URL to Gemini's OpenAI-compatible endpoint.

    `https://generativelanguage.googleapis.com` is the obvious thing to put in
    LLM_BASE_URL, and it is *wrong* — the OpenAI-compatible surface lives under
    `/v1beta/openai`. Posting to the bare host returns a bare 404 with no hint,
    which reads as "the model is gone" and sends you chasing the wrong bug.

    So accept the host and finish the path. Anyone who has already pointed at a
    full OpenAI-compatible URL (their own proxy, a gateway) is left alone.
    """
    base = (configured or DEFAULT_GEMINI_BASE_URL).rstrip("/")
    if base.endswith("/openai") or "/v1" in base:
        return base
    return f"{base}/v1beta/openai"

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
    """Parse a JSON object out of a model reply, tolerating fences and chatter.

    Even in JSON mode, models append prose — Gemini in particular will happily
    emit ``{"ok": true}`` and then keep talking. Scanning from the first ``{`` to
    the *last* ``}`` looks like it handles that, but it breaks the moment the
    trailing chatter contains a brace of its own: the slice then runs past the end
    of the real object and fails to parse, and a perfectly good answer is thrown
    away as "non-JSON".

    So decode the first complete object and ignore whatever follows.
    """
    body = text.strip()
    if body.startswith("```"):
        body = body.split("\n", 1)[-1] if "\n" in body else ""
        body = body.rsplit("```", 1)[0]

    start = body.find("{")
    if start == -1:
        return None

    try:
        parsed, _end = json.JSONDecoder().raw_decode(body[start:])
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

        # A 429 is not a failure, it is a *wait*. Falling straight back to the
        # template on a rate limit throws away an answer the provider was willing
        # to give — and on a free-tier key, which rate-limits aggressively, that is
        # most of them. Retry a couple of times with backoff, then give up
        # honestly. Bounded: a run must never hang on a quota that is exhausted for
        # the day rather than merely busy.
        for attempt in range(RATE_LIMIT_RETRIES):
            try:
                raw = self._raw_complete(system, user, schema, budget)
                break
            except Exception as exc:  # noqa: BLE001
                if not _is_rate_limited(exc) or attempt == RATE_LIMIT_RETRIES - 1:
                    self._fail(
                        f"LLM call failed ({self.settings.llm_provider.value}): {exc}"
                    )
                    return None
                delay = RATE_LIMIT_BACKOFF * (2**attempt)
                logger.warning("rate limited; retrying in %.0fs", delay)
                time.sleep(delay)

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
        if provider is LLMProvider.gemini:
            return self._complete_gemini(system, user, max_tokens)
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

    def _complete_gemini(self, system: str, user: str, max_tokens: int) -> str:
        """Gemini via its OpenAI-compatible surface.

        Same wire format as `_complete_openai`, different host and a different
        failure mode worth naming: Google retires model ids, and a retired id
        answers **404**, not 400. Left unexplained that reads as "the endpoint is
        wrong" and sends you debugging the URL, which is fine. The message below
        says what is actually true — the id is dead — and how to find a live one.
        """
        import httpx

        model = self.settings.llm_model
        if not model:
            raise RuntimeError("LLM_MODEL is required when LLM_PROVIDER=gemini")

        base_url = _gemini_base_url(self.settings.llm_base_url)

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
        # only "404 Not Found", hiding the part that says *why* — which is what
        # turns a debuggable failure into a silent fallback.
        try:
            body = response.json()
        except ValueError:
            body = {}

        # Gemini returns its error wrapped in a single-element LIST, not a bare
        # object like every other OpenAI-compatible provider. Unwrap it, or the
        # message below never fires and the caller is told nothing.
        if isinstance(body, list) and body:
            body = body[0]

        if isinstance(body, dict) and body.get("error"):
            err = body["error"]
            message = err.get("message") if isinstance(err, dict) else err
            if response.status_code == 404:
                message = (
                    f"{message} (LLM_MODEL={model!r}). List the ids your key can "
                    f"actually reach with: GET "
                    f"https://generativelanguage.googleapis.com/v1beta/models"
                    f"?key=$LLM_API_KEY"
                )
            raise RuntimeError(f"HTTP {response.status_code}: {message}")

        response.raise_for_status()
        return body["choices"][0]["message"]["content"]
