"""Shared HTTP client settings."""

from __future__ import annotations

import httpx

from .._version import __version__

USER_AGENT = f"safepyguard/{__version__}"


def make_client(timeout: float = 15.0) -> httpx.Client:
    """An httpx client with a polite User-Agent and retries on connection errors."""
    return httpx.Client(
        timeout=timeout,
        headers={"User-Agent": USER_AGENT},
        transport=httpx.HTTPTransport(retries=2),
        follow_redirects=True,
    )
