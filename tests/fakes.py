"""In-memory stand-ins for PyPI and OSV so tests never touch the network."""

from __future__ import annotations

import json
from typing import Any

import httpx
from packaging.utils import canonicalize_name
from packaging.version import Version

# The real ids of the requests 2.19.0 credential-leak advisory, used across tests.
GHSA = "GHSA-x84v-xcm2-53pg"
PYSEC = "PYSEC-2018-28"
CVE = "CVE-2018-18074"


def osv_record(
    vuln_id: str,
    *,
    package: str = "requests",
    aliases: tuple[str, ...] = (),
    summary: str = "",
    severity: str | None = None,
    cvss: str | None = None,
    introduced: str = "0",
    fixed: str | None = None,
    withdrawn: str | None = None,
) -> dict[str, Any]:
    events: list[dict[str, str]] = [{"introduced": introduced}]
    if fixed:
        events.append({"fixed": fixed})
    record: dict[str, Any] = {
        "id": vuln_id,
        "aliases": list(aliases),
        "summary": summary,
        "affected": [
            {
                "package": {"name": package, "ecosystem": "PyPI"},
                "ranges": [{"type": "ECOSYSTEM", "events": events}],
            }
        ],
    }
    if severity:
        record["database_specific"] = {"severity": severity}
    if cvss:
        record["severity"] = [{"type": "CVSS_V3", "score": cvss}]
    if withdrawn:
        record["withdrawn"] = withdrawn
    return record


class FakeAPI:
    def __init__(self) -> None:
        self.packages: dict[str, dict[str, dict[str, Any]]] = {}
        self.osv_hits: dict[tuple[str, str], list[str]] = {}
        self.osv_records: dict[str, dict[str, Any]] = {}
        self.calls: list[str] = []
        self.down_hosts: set[str] = set()

    def add_package(
        self,
        name: str,
        version: str,
        *,
        license: str | None = None,
        license_expression: str | None = None,
        classifiers: tuple[str, ...] = (),
        yanked: bool = False,
    ) -> None:
        info = {
            "name": name,
            "version": version,
            "license": license,
            "license_expression": license_expression,
            "classifiers": list(classifiers),
        }
        self.packages.setdefault(canonicalize_name(name), {})[version] = {
            "info": info,
            "yanked": yanked,
        }

    def add_vuln(self, name: str, version: str, record: dict[str, Any]) -> None:
        self.osv_hits.setdefault((canonicalize_name(name), version), []).append(record["id"])
        self.osv_records[record["id"]] = record

    def client(self) -> httpx.Client:
        return httpx.Client(transport=httpx.MockTransport(self.handler))

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.calls.append(f"{request.method} {request.url}")
        if request.url.host in self.down_hosts:
            raise httpx.ConnectError("connection refused", request=request)
        if request.url.host == "pypi.org":
            return self._pypi(request)
        if request.url.host == "api.osv.dev":
            return self._osv(request)
        return httpx.Response(404)

    def _pypi(self, request: httpx.Request) -> httpx.Response:
        parts = request.url.path.strip("/").split("/")  # pypi/<name>[/<version>]/json
        versions = self.packages.get(canonicalize_name(parts[1]))
        if not versions:
            return httpx.Response(404)
        if len(parts) == 4:
            entry = versions.get(parts[2])
            if entry is None:
                return httpx.Response(404)
            return httpx.Response(200, json={"info": entry["info"]})
        latest = max(versions, key=Version)
        releases = {
            version: [{"filename": f"pkg-{version}.tar.gz", "yanked": entry["yanked"]}]
            for version, entry in versions.items()
        }
        return httpx.Response(200, json={"info": versions[latest]["info"], "releases": releases})

    def _osv(self, request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/querybatch":
            queries = json.loads(request.content)["queries"]
            results = []
            for query in queries:
                key = (canonicalize_name(query["package"]["name"]), query["version"])
                ids = self.osv_hits.get(key, [])
                results.append({"vulns": [{"id": i} for i in ids]} if ids else {})
            return httpx.Response(200, json={"results": results})
        if request.url.path.startswith("/v1/vulns/"):
            record = self.osv_records.get(request.url.path.rsplit("/", 1)[1])
            return httpx.Response(200, json=record) if record else httpx.Response(404)
        return httpx.Response(404)
