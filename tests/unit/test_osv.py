from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

from fakes import osv_record
from safepyguard.cache import JsonCache
from safepyguard.errors import SourceError
from safepyguard.models import Severity
from safepyguard.sources.osv import (
    OSVClient,
    build_vulnerabilities,
    cvss3_base_score,
    fixed_versions,
    pick_fix_version,
    record_severity,
    severity_from_score,
)


@pytest.mark.parametrize(
    ("vector", "score"),
    [
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
        ("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N", 5.3),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
        ("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:N", 0.0),
        ("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H", 9.1),
        ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", None),
        ("CVSS:3.1/AV:N/AC:L", None),
        ("garbage", None),
    ],
)
def test_cvss3_base_score(vector: str, score: float | None) -> None:
    assert cvss3_base_score(vector) == score


@pytest.mark.parametrize(
    ("score", "severity"),
    [(9.8, Severity.CRITICAL), (7.0, Severity.HIGH), (5.3, Severity.MODERATE), (0.0, Severity.LOW)],
)
def test_severity_from_score(score: float, severity: Severity) -> None:
    assert severity_from_score(score) is severity


def test_record_severity_prefers_advisory_label() -> None:
    record = osv_record(
        "X", severity="MODERATE", cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    )
    assert record_severity(record) == (Severity.MODERATE, 9.8)


def test_record_severity_falls_back_to_cvss_then_unknown() -> None:
    assert record_severity(
        osv_record("X", cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    ) == (
        Severity.CRITICAL,
        9.8,
    )
    assert record_severity(osv_record("X", severity="MEDIUM")) == (Severity.MODERATE, None)
    assert record_severity(osv_record("X", severity="weird")) == (Severity.UNKNOWN, None)
    assert record_severity(osv_record("X")) == (Severity.UNKNOWN, None)


def test_fixed_versions_only_for_matching_package() -> None:
    record = osv_record("X", package="Requests", fixed="2.20.0")
    record["affected"].append(
        {
            "package": {"name": "other", "ecosystem": "PyPI"},
            "ranges": [{"type": "ECOSYSTEM", "events": [{"fixed": "9.9"}]}],
        }
    )
    record["affected"][0]["ranges"].append({"type": "GIT", "events": [{"fixed": "abc123"}]})
    assert fixed_versions(record, "requests") == ["2.20.0"]


@pytest.mark.parametrize(
    ("installed", "fixed", "expected"),
    [
        ("1.0", ["1.2.3", "2.0.5"], "1.2.3"),
        ("2.0.1", ["1.2.3", "2.0.5"], "2.0.5"),
        ("3.0", ["1.2.3", "2.0.5"], None),
        ("1.0", ["not-a-version", "1.1"], "1.1"),
        ("not-a-version", ["1.1"], None),
    ],
)
def test_pick_fix_version(installed: str, fixed: list[str], expected: str | None) -> None:
    assert pick_fix_version(installed, fixed) == expected


def test_duplicate_records_are_merged() -> None:
    records = [
        osv_record("PYSEC-1", aliases=("CVE-1",), fixed="2.20.0"),
        osv_record(
            "GHSA-1", aliases=("CVE-1",), summary="Bad thing", severity="HIGH", fixed="2.20.0"
        ),
        osv_record("GHSA-2", summary="Other thing", severity="LOW"),
        osv_record("PYSEC-3", summary="Withdrawn", withdrawn="2024-01-01T00:00:00Z"),
    ]
    vulns = build_vulnerabilities(records, "requests", "2.19.0")
    assert [v.id for v in vulns] == ["GHSA-1", "GHSA-2"]
    first = vulns[0]
    assert first.aliases == ["CVE-1", "PYSEC-1"]
    assert first.severity is Severity.HIGH
    assert first.summary == "Bad thing"
    assert first.fix_version == "2.20.0"
    assert first.cves == ["CVE-1"]
    assert first.url == "https://osv.dev/vulnerability/GHSA-1"
    assert vulns[1].fix_version is None


def test_record_linking_two_groups_merges_them() -> None:
    records = [
        osv_record("GHSA-a", aliases=("CVE-a",)),
        osv_record("PYSEC-b", aliases=("CVE-b",)),
        osv_record("OSV-c", aliases=("CVE-a", "CVE-b")),
    ]
    vulns = build_vulnerabilities(records, "requests", "1.0")
    assert len(vulns) == 1
    assert vulns[0].id == "GHSA-a"
    assert vulns[0].aliases == ["CVE-a", "CVE-b", "OSV-c", "PYSEC-b"]


def test_summary_falls_back_to_details() -> None:
    record = osv_record("PYSEC-9")
    record["details"] = "First line\nSecond line"
    assert build_vulnerabilities([record], "requests", "1.0")[0].summary == "First line"


def _osv_client(handler: Any, cache: JsonCache | None = None) -> OSVClient:
    return OSVClient(httpx.Client(transport=httpx.MockTransport(handler)), cache)


def test_query_batch_follows_pagination_and_caches(tmp_path: Any) -> None:
    calls: list[list[dict[str, Any]]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        queries = json.loads(request.content)["queries"]
        calls.append(queries)
        results = []
        for query in queries:
            if query["package"]["name"] == "a" and "page_token" not in query:
                results.append({"vulns": [{"id": "V1"}], "next_page_token": "t1"})
            elif query["package"]["name"] == "a":
                results.append({"vulns": [{"id": "V2"}, {"id": "V1"}]})
            else:
                results.append({})
        return httpx.Response(200, json={"results": results})

    cache = JsonCache(tmp_path)
    client = _osv_client(handler, cache)
    assert client.query_batch([("a", "1.0"), ("b", "2.0")]) == [["V1", "V2"], []]
    assert len(calls) == 2
    assert calls[1] == [
        {"package": {"name": "a", "ecosystem": "PyPI"}, "version": "1.0", "page_token": "t1"}
    ]
    # Second time everything comes from the cache.
    assert client.query_batch([("a", "1.0"), ("b", "2.0")]) == [["V1", "V2"], []]
    assert len(calls) == 2


def test_osv_errors_raise_source_error() -> None:
    def down(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    with pytest.raises(SourceError, match="could not reach OSV"):
        _osv_client(down).get_vulnerability("X")
    with pytest.raises(SourceError, match="HTTP 500"):
        _osv_client(lambda r: httpx.Response(500)).get_vulnerability("X")
    with pytest.raises(SourceError, match="invalid JSON"):
        _osv_client(lambda r: httpx.Response(200, text="nope")).get_vulnerability("X")
    with pytest.raises(SourceError, match="unexpected data"):
        _osv_client(lambda r: httpx.Response(200, json=[1])).get_vulnerability("X")
