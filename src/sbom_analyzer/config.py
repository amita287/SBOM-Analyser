"""Runtime settings, loaded from environment / `.env`.

Only three variables are contractually required (see `.env.example`):
`LLM_PROVIDER`, `LLM_API_KEY`, `LLM_MODEL`. Data/report directories are
derived with sensible defaults so scripts work out of the box.
"""

from __future__ import annotations

import os
from enum import Enum
from functools import lru_cache
from pathlib import Path

from dotenv import load_dotenv
from pydantic import BaseModel

# project root == two levels up from src/sbom_analyzer/config.py
PROJECT_ROOT = Path(__file__).resolve().parents[2]


class LLMProvider(str, Enum):
    none = "none"
    openai = "openai"
    anthropic = "anthropic"
    gemini= "gemini"


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    try:
        return int(raw) if raw and raw.strip() else default
    except ValueError:
        return default


class Settings(BaseModel):
    """Validated view of the environment."""

    llm_provider: LLMProvider = LLMProvider.none
    llm_api_key: str = ""
    llm_model: str = ""
    llm_base_url: str = ""  # OpenAI-compatible endpoints only

    # Do the LLM adjudications (Reasoners A/B) feed the risk score?
    # Default False: verdicts are recorded on the report, but every number that
    # feeds a metric stays deterministic. See `.env.example` for the trade-off.
    llm_affects_score: bool = False
    # Cap LLM enrichment to the N riskiest findings so a demo run stays cheap.
    llm_max_findings: int = 10
    # Dependencies per Reasoner-B request. There are 301 to judge and a free-tier
    # key allows a couple of dozen requests a day, so one call per dependency
    # simply cannot run. Bigger batches mean fewer calls but a longer reply — past
    # ~30 the model starts truncating.
    llm_batch_size: int = 25

    # Does a POTENTIAL match (right library, version not in the advisory's affected
    # list) count as a vulnerability?
    #
    # This single flag is the difference between the two ways a scanner can be
    # wrong, and there is no setting that is right for every dataset:
    #
    #   False (default) — potentials COUNT. Catches everything; over-flags when an
    #                     advisory names a library whose version you do not run.
    #                     On the supplied dataset this is the only setting that
    #                     detects anything at all: not one of the 500 dependency
    #                     versions appears in its own library's affected list, so
    #                     strict matching finds ZERO CVEs while the ground truth
    #                     marks 176 vulnerable.
    #
    #   True (strict)   — only CONFIRMED matches count. What a scanner should do
    #                     when its advisory data is trustworthy: near-zero false
    #                     positives. On this dataset it drops recall to zero.
    #
    # Potentials are still detected, scored and shown either way. This only decides
    # whether they set a risk TYPE — i.e. whether they make a dependency "risky".
    strict_version_matching: bool = False
    # Per-call output budget. Lower it if your provider rejects the request for
    # cost reasons (e.g. OpenRouter returns 402 when max_tokens exceeds credit).
    llm_max_tokens: int = 1024

    data_dir: Path = PROJECT_ROOT / "data"
    reports_dir: Path = PROJECT_ROOT / "reports"

    @property
    def llm_enabled(self) -> bool:
        return self.llm_provider is not LLMProvider.none


def load_settings() -> Settings:
    """Read `.env` (if present) plus the process environment into `Settings`."""
    load_dotenv()
    provider = (os.getenv("LLM_PROVIDER") or "none").strip().lower() or "none"
    return Settings(
        llm_provider=provider,
        llm_api_key=os.getenv("LLM_API_KEY", ""),
        llm_model=os.getenv("LLM_MODEL", ""),
        llm_base_url=os.getenv("LLM_BASE_URL", ""),
        llm_affects_score=_env_bool("LLM_AFFECTS_SCORE", False),
        strict_version_matching=_env_bool("STRICT_VERSION_MATCHING", False),
        llm_max_findings=_env_int("LLM_MAX_FINDINGS", 10),
        llm_batch_size=_env_int("LLM_BATCH_SIZE", 25),
        llm_max_tokens=_env_int("LLM_MAX_TOKENS", 1024),
        data_dir=Path(os.getenv("DATA_DIR", str(PROJECT_ROOT / "data"))),
        reports_dir=Path(os.getenv("REPORTS_DIR", str(PROJECT_ROOT / "reports"))),
    )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Cached settings singleton for the process."""
    return load_settings()
