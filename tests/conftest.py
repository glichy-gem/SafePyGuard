from __future__ import annotations

import textwrap
from collections.abc import Callable
from pathlib import Path

import pytest

from fakes import CVE, GHSA, PYSEC, FakeAPI, osv_record
from safepyguard import Report, scan


@pytest.fixture(autouse=True)
def isolated_cache(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Never read or write the real user cache during tests."""
    cache_dir = tmp_path / "cache"
    monkeypatch.setattr("safepyguard.cache.default_cache_dir", lambda: cache_dir)
    return cache_dir


@pytest.fixture
def write_requirements(tmp_path: Path) -> Callable[..., Path]:
    def write(text: str, name: str = "requirements.txt") -> Path:
        path = tmp_path / name
        path.write_text(textwrap.dedent(text), encoding="utf-8")
        return path

    return write


@pytest.fixture
def api() -> FakeAPI:
    """A small fake ecosystem with one package per interesting case."""
    fake = FakeAPI()
    fake.add_package(
        "requests",
        "2.19.0",
        license="Apache 2.0",
        classifiers=("License :: OSI Approved :: Apache Software License",),
    )
    fake.add_package("requests", "2.32.3", license="Apache 2.0")
    fake.add_package(
        "PyQt5",
        "5.15.0",
        license="GPL v3",
        classifiers=("License :: OSI Approved :: GNU General Public License v3 (GPLv3)",),
    )
    fake.add_package("numpy", "1.26.4", license_expression="BSD-3-Clause")
    fake.add_package("numpy", "2.0.0", license_expression="BSD-3-Clause", yanked=True)
    fake.add_package("numpy", "2.1.0", license_expression="BSD-3-Clause")
    fake.add_package("numpy", "2.2.0rc1", license_expression="BSD-3-Clause")
    fake.add_package("certifi", "2024.8.30", license="MPL-2.0")
    fake.add_package("mystery", "1.0", license="Some custom terms")

    fake.add_vuln(
        "requests",
        "2.19.0",
        osv_record(
            GHSA,
            aliases=(CVE,),
            summary="Insufficiently Protected Credentials",
            severity="HIGH",
            fixed="2.20.0",
        ),
    )
    fake.add_vuln(
        "requests",
        "2.19.0",
        osv_record(PYSEC, aliases=(CVE, GHSA), fixed="2.20.0"),
    )
    return fake


@pytest.fixture
def use_fake_network(api: FakeAPI, monkeypatch: pytest.MonkeyPatch) -> FakeAPI:
    """Make scan() (and so the CLI) talk to the fake API."""
    monkeypatch.setattr("safepyguard.scanner.make_client", lambda timeout=15.0: api.client())
    return api


@pytest.fixture
def report(api: FakeAPI, write_requirements: Callable[..., Path]) -> Report:
    """A finished scan with one approved+vulnerable, one denied and one restricted package."""
    path = write_requirements("requests==2.19.0\nPyQt5==5.15.0\nnumpy\ncertifi==2024.8.30\n")
    return scan(path, client=api.client(), cache=False)
