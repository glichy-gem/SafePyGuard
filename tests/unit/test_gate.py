from __future__ import annotations

import pytest

from safepyguard import Category, Report, Severity, evaluate
from safepyguard.gate import fails_severity
from safepyguard.models import Dependency, PackageResult, Vulnerability


def _report_with(severity: Severity) -> Report:
    dep = Dependency("pkg", "==1.0", "1.0", "requirements.txt", 1)
    vuln = Vulnerability("V-1", "bad", severity)
    return Report("requirements.txt", "<test>", [PackageResult(dep, "1.0", vulnerabilities=[vuln])])


@pytest.mark.parametrize(
    ("severity", "threshold", "fails"),
    [
        (Severity.HIGH, Severity.HIGH, True),
        (Severity.CRITICAL, Severity.HIGH, True),
        (Severity.MODERATE, Severity.HIGH, False),
        (Severity.UNKNOWN, Severity.CRITICAL, True),
        (Severity.LOW, Severity.LOW, True),
    ],
)
def test_fails_severity(severity: Severity, threshold: Severity, fails: bool) -> None:
    assert fails_severity(severity, threshold) is fails
    gate = evaluate(_report_with(severity), [], threshold)
    assert gate.passed is not fails


def test_gate_with_everything_disabled(report: Report) -> None:
    gate = evaluate(report, fail_on_license=[], fail_on_severity=None)
    assert gate.passed
    assert gate.reasons == []


def test_gate_orders_license_reasons_by_strictness(report: Report) -> None:
    gate = evaluate(report, [Category.RESTRICTED, Category.DENIED], None)
    assert gate.reasons == ["denied license: PyQt5", "restricted license: certifi"]
    assert gate.to_dict()["fail_on_license"] == ["denied", "restricted"]
