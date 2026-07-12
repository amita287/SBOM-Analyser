"""On-disk cache for LLM verdicts.

The free-tier Gemini key allows a couple of dozen requests a day, and this dataset
has 301 dependencies to adjudicate. Without a cache, a second `run_analysis` on
the same day gets nothing but 429s and silently degrades to templates — the run
would *look* LLM-enabled and be anything but.

Keyed by the facts the verdict actually depends on (library, version, and the CVE
ids filed against it), NOT by dependency id: two applications running the same
library at the same version are the same question, and it should only be asked
once. On this dataset that is not a big win — all 301 pairs are distinct — but it
is the correct key, and it makes the cache stable across dataset edits that only
renumber rows.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class VerdictCache:
    """A tiny JSON-file cache. Never raises: a broken cache must not stop a run."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._data: dict[str, Any] = {}
        self.hits = 0
        self.misses = 0

        if path.is_file():
            try:
                self._data = json.loads(path.read_text(encoding="utf-8"))
            except Exception:  # noqa: BLE001 — a corrupt cache is a cold cache
                self._data = {}

    @staticmethod
    def key(library: str, version: str, cve_ids: list[str]) -> str:
        return f"{library}@{version}|{','.join(sorted(cve_ids))}"

    def get(self, key: str) -> dict[str, Any] | None:
        hit = self._data.get(key)
        if hit is None:
            self.misses += 1
        else:
            self.hits += 1
        return hit

    def put(self, key: str, value: dict[str, Any]) -> None:
        self._data[key] = value

    def save(self) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(
                json.dumps(self._data, indent=2, sort_keys=True), encoding="utf-8"
            )
        except Exception:  # noqa: BLE001 — failing to persist is not fatal
            pass
