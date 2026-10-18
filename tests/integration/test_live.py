"""Calls the real PyPI and OSV APIs. Skipped by default; run with ``pytest -m network``."""

from __future__ import annotations

from pathlib import Path

import pytest

from safepyguard import Category, scan

pytestmark = pytest.mark.network


def test_live_scan(tmp_path: Path) -> None:
    requirements = tmp_path / "requirements.txt"
    requirements.write_text("requests==2.19.0\n", encoding="utf-8")
    report = scan(requirements, cache=False)
    package = report.packages[0]
    assert package.license.category is Category.APPROVED
    ids = {name for v in package.vulnerabilities for name in (v.id, *v.aliases)}
    assert "CVE-2018-18074" in ids
