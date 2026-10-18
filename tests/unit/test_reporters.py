from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

from fakes import GHSA, FakeAPI
from safepyguard import Report, evaluate, scan
from safepyguard.reporters import render


def test_json(report: Report) -> None:
    data = json.loads(render("json", report, evaluate(report)))
    assert data["tool"]["name"] == "safepyguard"
    assert data["gate"]["passed"] is False
    assert data["gate"]["fail_on_severity"] == "high"
    assert data["summary"]["packages"] == 4
    assert data["summary"]["licenses"]["denied"] == 1
    requests = data["packages"][0]
    assert requests["license"]["expression"] == "Apache-2.0"
    assert requests["vulnerabilities"][0]["id"] == GHSA
    assert requests["vulnerabilities"][0]["severity"] == "high"
    assert requests["recommended_version"] == "2.20.0"
    assert data["packages"][2]["pinned"] is False


def test_sarif(report: Report) -> None:
    data = json.loads(render("sarif", report, evaluate(report)))
    run = data["runs"][0]
    assert data["version"] == "2.1.0"
    rule_ids = {rule["id"] for rule in run["tool"]["driver"]["rules"]}
    assert rule_ids == {"license-denied", "license-restricted", GHSA}
    levels = {(r["ruleId"], r["level"]) for r in run["results"]}
    assert levels == {
        ("license-denied", "error"),
        ("license-restricted", "warning"),
        (GHSA, "error"),
    }
    location = run["results"][0]["locations"][0]["physicalLocation"]
    assert location["artifactLocation"]["uri"].endswith("requirements.txt")
    assert location["region"]["startLine"] in (1, 2)
    vuln_rule = next(r for r in run["tool"]["driver"]["rules"] if r["id"] == GHSA)
    assert vuln_rule["properties"]["security-severity"] == "8.0"


def test_markdown(report: Report) -> None:
    text = render("markdown", report, evaluate(report))
    assert "**Result: FAILED**" in text
    assert (
        "| requests | 2.19.0 | Apache-2.0 | approved | 1 (worst: high), upgrade to 2.20.0 |" in text
    )
    assert "| numpy | 2.1.0 (unpinned) | BSD-3-Clause | approved | none |" in text
    assert f"[{GHSA}](https://osv.dev/vulnerability/{GHSA})" in text


def test_table_text(report: Report) -> None:
    text = render("table", report, evaluate(report))
    assert "requests" in text
    assert "DENIED" in text
    assert "Vulnerability details" in text
    assert "fixed in 2.20.0" in text
    assert "FAILED" in text


def test_reports_without_vulnerability_check(
    api: FakeAPI, write_requirements: Callable[..., Path]
) -> None:
    path = write_requirements("click==8.1.7\nghost==1\n# comment\n-e .\n")
    api.add_package("click", "8.1.7", license="BSD-3-Clause")
    report = scan(path, client=api.client(), cache=False, vulnerabilities=False)
    gate = evaluate(report)
    table = render("table", report, gate)
    assert "Vulnerabilities" not in table
    assert "PASSED" in table
    assert "warning:" in table
    markdown = render("markdown", report, gate)
    assert "### Notes" in markdown
    assert "Vulnerabilities" not in markdown.split("### Notes")[0]
