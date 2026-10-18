"""The CI gate: decide whether a report passes or fails."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from .models import Category, Report, Severity


@dataclass
class GateResult:
    passed: bool
    reasons: list[str] = field(default_factory=list)
    fail_on_license: frozenset[Category] = frozenset()
    fail_on_severity: Severity | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "reasons": self.reasons,
            "fail_on_license": sorted(c.value for c in self.fail_on_license),
            "fail_on_severity": self.fail_on_severity.label if self.fail_on_severity else None,
        }


def fails_severity(severity: Severity, threshold: Severity) -> bool:
    """Unknown severities fail too: if we can't tell how bad it is, a human should look."""
    return severity is Severity.UNKNOWN or severity >= threshold


def evaluate(
    report: Report,
    fail_on_license: Iterable[Category] = (Category.DENIED,),
    fail_on_severity: Severity | None = Severity.HIGH,
) -> GateResult:
    license_set = frozenset(fail_on_license)
    reasons = []

    if report.checked_licenses:
        for category in sorted(license_set, key=lambda c: -c.rank):
            names = [p.name for p in report.packages if p.license.category is category]
            if names:
                reasons.append(f"{category.value} license: {', '.join(names)}")

    if report.checked_vulnerabilities and fail_on_severity is not None:
        failing = []
        for package in report.packages:
            count = sum(
                fails_severity(v.severity, fail_on_severity) for v in package.vulnerabilities
            )
            if count:
                failing.append(f"{package.name} ({count})")
        if failing:
            reasons.append(
                f"vulnerabilities at or above {fail_on_severity.label} severity: "
                + ", ".join(failing)
            )

    return GateResult(
        passed=not reasons,
        reasons=reasons,
        fail_on_license=license_set,
        fail_on_severity=fail_on_severity,
    )
