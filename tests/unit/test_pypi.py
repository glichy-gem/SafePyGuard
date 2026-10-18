from __future__ import annotations

import time
from pathlib import Path

import httpx
import pytest

from fakes import FakeAPI
from safepyguard.cache import JsonCache
from safepyguard.errors import PackageNotFoundError, SourceError
from safepyguard.sources.pypi import PyPIClient


def test_get_metadata(api: FakeAPI) -> None:
    meta = PyPIClient(api.client()).get_metadata("requests", "2.19.0")
    assert meta.name == "requests"
    assert meta.version == "2.19.0"
    assert meta.license == "Apache 2.0"
    assert meta.license_expression is None
    assert meta.classifiers == ["License :: OSI Approved :: Apache Software License"]


def test_resolve_version_skips_yanked_and_prereleases(api: FakeAPI) -> None:
    client = PyPIClient(api.client())
    assert client.resolve_version("numpy") == "2.1.0"
    assert client.resolve_version("numpy", "<2") == "1.26.4"
    assert client.resolve_version("numpy", ">=2.2.0rc1") == "2.2.0rc1"
    with pytest.raises(PackageNotFoundError, match="no release of numpy"):
        client.resolve_version("numpy", ">=5")


def test_not_found(api: FakeAPI) -> None:
    client = PyPIClient(api.client())
    with pytest.raises(PackageNotFoundError, match=r"nope==1\.0 was not found"):
        client.get_metadata("nope", "1.0")
    with pytest.raises(PackageNotFoundError):
        client.get_metadata("requests", "0.0.1")


def test_cache_avoids_second_request(api: FakeAPI, tmp_path: Path) -> None:
    client = PyPIClient(api.client(), JsonCache(tmp_path))
    client.resolve_version("numpy")
    # The project page carried the latest metadata, so this needs no request.
    calls = len(api.calls)
    assert client.get_metadata("numpy", "2.2.0rc1").license_expression == "BSD-3-Clause"
    assert len(api.calls) == calls
    client.get_metadata("requests", "2.19.0")
    client.get_metadata("requests", "2.19.0")
    assert len(api.calls) == calls + 1


@pytest.mark.parametrize(
    ("response", "message"),
    [
        (httpx.Response(503), "HTTP 503"),
        (httpx.Response(200, text="<html>"), "invalid JSON"),
        (httpx.Response(200, json=["x"]), "unexpected data"),
    ],
)
def test_pypi_errors(response: httpx.Response, message: str) -> None:
    client = PyPIClient(httpx.Client(transport=httpx.MockTransport(lambda r: response)))
    with pytest.raises(SourceError, match=message):
        client.get_metadata("requests", "2.19.0")


def test_pypi_unreachable(api: FakeAPI) -> None:
    api.down_hosts.add("pypi.org")
    with pytest.raises(SourceError, match="could not reach PyPI"):
        PyPIClient(api.client()).get_metadata("requests", "2.19.0")


def test_json_cache_round_trip_and_expiry(tmp_path: Path) -> None:
    cache = JsonCache(tmp_path, ttl=60)
    assert cache.get("k") is None
    cache.set("k", {"a": [1, 2]})
    assert cache.get("k") == {"a": [1, 2]}

    expired = JsonCache(tmp_path, ttl=-1)
    assert expired.get("k") is None

    disabled = JsonCache(tmp_path, enabled=False)
    disabled.set("other", 1)
    assert disabled.get("k") is None
    assert JsonCache(tmp_path).get("other") is None


def test_json_cache_ignores_corrupt_files(tmp_path: Path) -> None:
    cache = JsonCache(tmp_path)
    cache.set("k", 1)
    next(tmp_path.glob("*.json")).write_text("{not json", encoding="utf-8")
    assert cache.get("k") is None


def test_json_cache_write_failure_is_silent(tmp_path: Path) -> None:
    blocker = tmp_path / "file"
    blocker.write_text("x", encoding="utf-8")
    cache = JsonCache(blocker / "sub")  # parent is a file, so mkdir fails
    cache.set("k", 1)
    assert cache.get("k") is None


def test_default_cache_dir_is_patched(isolated_cache: Path) -> None:
    cache = JsonCache()
    assert cache.directory == isolated_cache
    cache.set("k", time.time())
    assert list(isolated_cache.glob("*.json"))
