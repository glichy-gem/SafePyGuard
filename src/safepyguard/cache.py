"""A tiny on-disk JSON cache so repeated scans don't hit the network every time."""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import threading
import time
from pathlib import Path
from typing import Any

from platformdirs import user_cache_dir

DEFAULT_TTL = 24 * 60 * 60  # one day, in seconds


def default_cache_dir() -> Path:
    return Path(user_cache_dir("safepyguard", appauthor=False))


class JsonCache:
    """Stores JSON values in files named after a hash of their key."""

    def __init__(
        self,
        directory: Path | str | None = None,
        *,
        ttl: float = DEFAULT_TTL,
        enabled: bool = True,
    ) -> None:
        self.directory = Path(directory) if directory is not None else default_cache_dir()
        self.ttl = ttl
        self.enabled = enabled

    def _path(self, key: str) -> Path:
        digest = hashlib.sha256(key.encode("utf-8")).hexdigest()
        return self.directory / f"{digest}.json"

    def get(self, key: str) -> Any:
        """Return the cached value, or None when it is missing, expired or unreadable."""
        if not self.enabled:
            return None
        try:
            with self._path(key).open(encoding="utf-8") as fh:
                entry = json.load(fh)
        except (OSError, ValueError):
            return None
        if not isinstance(entry, dict) or time.time() - entry.get("stored_at", 0) > self.ttl:
            return None
        return entry.get("value")

    def set(self, key: str, value: Any) -> None:
        """Store a value. A cache that can't be written is not an error."""
        if not self.enabled:
            return
        path = self._path(key)
        # Write to a temp file first so a crash never leaves a half-written entry.
        tmp = path.with_suffix(f".{os.getpid()}.{threading.get_ident()}.tmp")
        try:
            self.directory.mkdir(parents=True, exist_ok=True)
            tmp.write_text(json.dumps({"stored_at": time.time(), "value": value}), encoding="utf-8")
            os.replace(tmp, path)
        except OSError:
            with contextlib.suppress(OSError):
                tmp.unlink(missing_ok=True)
