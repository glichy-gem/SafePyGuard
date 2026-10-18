"""SARIF 2.1.0 report, which GitHub code scanning shows in the Security tab."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .._version import __version__
from ..gate import GateResult, fails_severity
from ..models import Category, Dependency, Report, Severity

# GitHub reads "security-severity" (0-10) to rank alerts when there is no CVSS score.
_FALLBACK_SCORES = {
    Severity.CRITICAL: 9.5,
    Severity.HIGH: 8.0,
    Severity.MODERATE: 5.5,
    Severity.LOW: 2.0,
    Severity.UNKNOWN: 5.0,
}


def render_sarif(report: Report, gate: GateResult) -> str:
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []

    for package in report.packages:
        location = _location(package.dependency)
        category = package.license.category
        if report.checked_licenses and category is not Category.APPROVED:
            rule_id = f"license-{category.value}"
            rules.setdefault(
                rule_id,
                {
                    "id": rule_id,
                    "name": f"License{category.value.title()}",
                    "shortDescription": {"text": f"Dependency license is {category.value}"},
                },
            )
            license_name = package.license.expression or package.license.raw or "no license"
            results.append(
                {
                    "ruleId": rule_id,
                    "level": "error" if category in gate.fail_on_license else "warning",
                    "message": {
                        "text": f"{package.name} {package.version or ''} is licensed under "
                        f"{license_name}, which the policy marks as {category.value}."
                    },
                    "locations": [location],
                }
            )

        for vuln in package.vulnerabilities:
            score = vuln.score if vuln.score is not None else _FALLBACK_SCORES[vuln.severity]
            rules.setdefault(
                vuln.id,
                {
                    "id": vuln.id,
                    "name": vuln.id,
                    "shortDescription": {"text": vuln.summary or vuln.id},
                    "helpUri": vuln.url,
                    "properties": {"security-severity": f"{score:.1f}", "tags": ["security"]},
                },
            )
            failing = gate.fail_on_severity is not None and fails_severity(
                vuln.severity, gate.fail_on_severity
            )
            fix = f" Upgrade to {vuln.fix_version}." if vuln.fix_version else ""
            results.append(
                {
                    "ruleId": vuln.id,
                    "level": "error" if failing else "warning",
                    "message": {
                        "text": f"{package.name} {package.version} is affected by {vuln.id} "
                        f"({vuln.severity.label}): {vuln.summary}.{fix}"
                    },
                    "locations": [location],
                }
            )

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "SafePyGuard",
                        "version": __version__,
                        "informationUri": "https://pypi.org/project/safepyguard/",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, indent=2)


def _location(dependency: Dependency) -> dict[str, Any]:
    path = Path(dependency.source)
    try:
        uri = path.resolve().relative_to(Path.cwd().resolve()).as_posix()
    except ValueError:
        uri = path.as_posix()
    return {
        "physicalLocation": {
            "artifactLocation": {"uri": uri},
            "region": {"startLine": dependency.line},
        }
    }
