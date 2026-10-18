from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

from fakes import CVE, GHSA, PYSEC, FakeAPI
from safepyguard import Category, Severity, evaluate, load_policy, scan
from safepyguard.errors import SourceError
from safepyguard.licenses.policy import parse_policy

DEMO = """
requests==2.19.0
PyQt5==5.15.0
numpy>=1.20
certifi==2024.8.30
mystery==1.0
ghost==0.1
"""


def test_end_to_end(api: FakeAPI, write_requirements: Callable[..., Path]) -> None:
    report = scan(write_requirements(DEMO), client=api.client(), cache=False)
    by_name = {p.name: p for p in report.packages}

    requests = by_name["requests"]
    assert requests.license.expression == "Apache-2.0"
    assert requests.license.category is Category.APPROVED
    assert len(requests.vulnerabilities) == 1
    vuln = requests.vulnerabilities[0]
    assert vuln.id == GHSA
    assert vuln.aliases == [CVE, PYSEC]
    assert vuln.severity is Severity.HIGH
    assert vuln.fix_version == "2.20.0"
    assert requests.recommended_version == "2.20.0"

    assert by_name["PyQt5"].license.expression == "GPL-3.0-only"
    assert by_name["PyQt5"].license.category is Category.DENIED
    assert by_name["numpy"].version == "2.1.0"
    assert by_name["numpy"].license.category is Category.APPROVED
    assert by_name["certifi"].license.category is Category.RESTRICTED
    assert by_name["mystery"].license.category is Category.UNKNOWN
    assert by_name["mystery"].license.raw == "Some custom terms"

    ghost = by_name["ghost"]
    assert ghost.license.category is Category.UNKNOWN
    assert ghost.errors == ["ghost==0.1 was not found on PyPI"]

    gate = evaluate(report)
    assert not gate.passed
    assert gate.reasons == [
        "denied license: PyQt5",
        "vulnerabilities at or above high severity: requests (1)",
    ]


def test_unpinned_unknown_package_skips_vulnerability_check(
    api: FakeAPI, write_requirements: Callable[..., Path]
) -> None:
    report = scan(write_requirements("ghost>=1\n"), client=api.client(), cache=False)
    assert report.packages[0].version is None
    assert report.packages[0].errors == [
        "ghost was not found on PyPI",
        "vulnerabilities not checked: version unknown",
    ]


def test_policy_exception_and_ignored_vulnerability(
    api: FakeAPI, write_requirements: Callable[..., Path]
) -> None:
    policy = parse_policy(
        """
        [licenses]
        approved = ["Apache-2.0"]
        [exceptions]
        pyqt5 = { category = "approved", reason = "commercial license" }
        [vulnerabilities]
        ignore = ["cve-2018-18074"]
        """
    )
    path = write_requirements("requests==2.19.0\nPyQt5==5.15.0\n")
    report = scan(path, policy, client=api.client(), cache=False)
    pyqt = report.packages[1]
    assert pyqt.license.category is Category.APPROVED
    assert pyqt.license.note == "policy exception: commercial license"
    assert report.packages[0].vulnerabilities == []
    assert report.ignored_vulnerabilities == [f"requests 2.19.0: {GHSA}"]
    assert evaluate(report, policy.fail_on_license, policy.fail_on_severity).passed


def test_ignore_argument(api: FakeAPI, write_requirements: Callable[..., Path]) -> None:
    path = write_requirements("requests==2.19.0\n")
    report = scan(path, client=api.client(), cache=False, ignore_vulnerabilities=[PYSEC])
    assert report.packages[0].vulnerabilities == []


def test_licenses_only_never_calls_osv(
    api: FakeAPI, write_requirements: Callable[..., Path]
) -> None:
    report = scan(write_requirements(DEMO), client=api.client(), cache=False, vulnerabilities=False)
    assert not any("osv.dev" in call for call in api.calls)
    assert not report.checked_vulnerabilities
    assert evaluate(report).reasons == ["denied license: PyQt5"]


def test_vulns_only_for_pinned_needs_no_pypi(
    api: FakeAPI, write_requirements: Callable[..., Path]
) -> None:
    report = scan(
        write_requirements("requests==2.19.0\n"), client=api.client(), cache=False, licenses=False
    )
    assert not any("pypi.org" in call for call in api.calls)
    assert report.packages[0].license.category is Category.UNKNOWN
    assert evaluate(report).reasons == ["vulnerabilities at or above high severity: requests (1)"]


def test_unreachable_source_raises(api: FakeAPI, write_requirements: Callable[..., Path]) -> None:
    api.down_hosts.add("api.osv.dev")
    with pytest.raises(SourceError):
        scan(write_requirements("requests==2.19.0\n"), client=api.client(), cache=False)


def test_scan_accepts_policy_path(
    api: FakeAPI, write_requirements: Callable[..., Path], tmp_path: Path
) -> None:
    policy_file = tmp_path / "p.toml"
    policy_file.write_text('[licenses]\ndenied = ["Apache-*"]\n', encoding="utf-8")
    report = scan(write_requirements("requests==2.19.0\n"), policy_file, client=api.client())
    assert report.policy == str(policy_file)
    assert report.packages[0].license.category is Category.DENIED


def test_uses_cache_between_scans(
    api: FakeAPI, write_requirements: Callable[..., Path], tmp_path: Path
) -> None:
    path = write_requirements(DEMO)
    scan(path, client=api.client(), cache_dir=tmp_path / "c")
    first = len(api.calls)
    scan(path, client=api.client(), cache_dir=tmp_path / "c")
    # Only the lookups that failed (ghost) are repeated.
    assert len(api.calls) - first == 1


def test_report_counts(api: FakeAPI, write_requirements: Callable[..., Path]) -> None:
    report = scan(write_requirements(DEMO), load_policy(), client=api.client(), cache=False)
    assert report.license_counts() == {"approved": 2, "restricted": 1, "denied": 1, "unknown": 2}
    assert report.severity_counts()["high"] == 1
    assert [p.name for p in report.vulnerable_packages] == ["requests"]
