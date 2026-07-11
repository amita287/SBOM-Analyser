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


class Settings(BaseModel):
    """Validated view of the environment."""

    llm_provider: LLMProvider = LLMProvider.none
    llm_api_key: str = ""
    llm_model: str = ""
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
        data_dir=Path(os.getenv("DATA_DIR", str(PROJECT_ROOT / "data"))),
        reports_dir=Path(os.getenv("REPORTS_DIR", str(PROJECT_ROOT / "reports"))),
    )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Cached settings singleton for the process."""
    return load_settings()
