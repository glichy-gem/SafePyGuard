"""Client for the OSV vulnerability database (https://osv.dev, https://google.github.io/osv.dev/api/)."""

from __future__ import annotations

import math
from collections.abc import Iterable, Sequence
from typing import Any

import httpx
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

from ..cache import JsonCache
from ..errors import SourceError
from ..models import Severity, Vulnerability, version_key

OSV_URL = "https://api.osv.dev/v1"
BATCH_SIZE = 1000  # OSV's limit for /querybatch


class OSVClient:
    def __init__(
        self,
        client: httpx.Client,
        cache: JsonCache | None = None,
        base_url: str = OSV_URL,
    ) -> None:
        self.client = client
        self.cache = cache or JsonCache(enabled=False)
        self.base_url = base_url.rstrip("/")

    def query_batch(self, packages: Sequence[tuple[str, str]]) -> list[list[str]]:
        """Vulnerability ids for each ``(name, version)``, in the same order."""
        found: dict[tuple[str, str], list[str]] = {}
        missing: list[tuple[str, str]] = []
        for name, version in packages:
            key = (str(canonicalize_name(name)), version)
            cached = self.cache.get(f"osv:query:{key[0]}:{version}")
            if cached is not None:
                found[key] = cached
            elif key not in found and key not in missing:
                missing.append(key)

        for package, ids in zip(missing, self._query_uncached(missing), strict=True):
            found[package] = ids
            self.cache.set(f"osv:query:{package[0]}:{package[1]}", ids)

        return [found[(canonicalize_name(name), version)] for name, version in packages]

    def get_vulnerability(self, vuln_id: str) -> dict[str, Any]:
        """The full OSV record for one id."""
        key = f"osv:vuln:{vuln_id}"
        record = self.cache.get(key)
        if record is None:
            record = self._request("GET", f"/vulns/{vuln_id}")
            self.cache.set(key, record)
        return dict(record)

    def _query_uncached(self, packages: Sequence[tuple[str, str]]) -> list[list[str]]:
        results: list[list[str]] = [[] for _ in packages]
        # (index into packages, page token); OSV pages results for packages with many vulns.
        pending: list[tuple[int, str | None]] = [(i, None) for i in range(len(packages))]
        while pending:
            chunk, pending = pending[:BATCH_SIZE], pending[BATCH_SIZE:]
            queries = []
            for index, token in chunk:
                name, version = packages[index]
                query: dict[str, Any] = {
                    "package": {"name": name, "ecosystem": "PyPI"},
                    "version": version,
                }
                if token:
                    query["page_token"] = token
                queries.append(query)
            data = self._request("POST", "/querybatch", {"queries": queries})
            batch = data.get("results") or []
            if len(batch) != len(chunk):
                raise SourceError(f"OSV answered {len(batch)} of {len(chunk)} queries")
            for (index, _), result in zip(chunk, batch, strict=True):
                results[index].extend(v["id"] for v in result.get("vulns") or [])
                if result.get("next_page_token"):
                    pending.append((index, result["next_page_token"]))
        return [list(dict.fromkeys(ids)) for ids in results]

    def _request(self, method: str, path: str, body: Any = None) -> dict[str, Any]:
        try:
            response = self.client.request(method, f"{self.base_url}{path}", json=body)
        except httpx.HTTPError as exc:
            raise SourceError(f"could not reach OSV: {exc}") from exc
        if response.is_error:
            raise SourceError(f"OSV returned HTTP {response.status_code} for {path}")
        try:
            data = response.json()
        except ValueError as exc:
            raise SourceError(f"OSV returned invalid JSON for {path}") from exc
        if not isinstance(data, dict):
            raise SourceError(f"OSV returned unexpected data for {path}")
        return data


# --------------------------------------------------------------------------- record parsing


def build_vulnerabilities(
    records: Iterable[dict[str, Any]], package: str, version: str
) -> list[Vulnerability]:
    """Turn OSV records into Vulnerability objects, merging duplicates.

    The same issue is often published twice (e.g. GHSA-... and PYSEC-...), with each
    record listing the other, or a shared CVE, as an alias. Those become one entry.
    """
    groups: list[list[dict[str, Any]]] = []
    owner: dict[str, int] = {}  # id or alias -> index into groups
    for record in records:
        if record.get("withdrawn"):
            continue
        names = {record["id"], *(record.get("aliases") or [])}
        hits = sorted({owner[n] for n in names if n in owner})
        if hits:
            target = hits[0]
            for other in hits[1:]:  # this record links two existing groups
                groups[target].extend(groups[other])
                groups[other] = []
                for name, group in owner.items():
                    if group == other:
                        owner[name] = target
            groups[target].append(record)
        else:
            target = len(groups)
            groups.append([record])
        for name in names:
            owner[name] = target

    vulnerabilities = [_merge(group, package, version) for group in groups if group]
    vulnerabilities.sort(key=lambda v: (-v.severity, v.id))
    return vulnerabilities


def _merge(group: list[dict[str, Any]], package: str, version: str) -> Vulnerability:
    primary = min(group, key=lambda r: (_id_priority(r["id"]), r["id"]))
    aliases = {r["id"] for r in group} | {a for r in group for a in r.get("aliases") or []}
    aliases.discard(primary["id"])

    severities = [record_severity(r) for r in group]
    scores = [score for _, score in severities if score is not None]
    summary = next((r["summary"] for r in (primary, *group) if r.get("summary")), "")
    if not summary:
        summary = (primary.get("details") or primary["id"]).strip().splitlines()[0][:200]

    fixed = sorted({f for r in group for f in fixed_versions(r, package)}, key=version_key)
    return Vulnerability(
        id=primary["id"],
        summary=summary,
        severity=max(severity for severity, _ in severities),
        score=max(scores) if scores else None,
        aliases=sorted(aliases),
        fixed_versions=fixed,
        fix_version=pick_fix_version(version, fixed),
        url=f"https://osv.dev/vulnerability/{primary['id']}",
    )


def _id_priority(vuln_id: str) -> int:
    # GitHub advisories carry the best severity data, so prefer them as the display id.
    for priority, prefix in enumerate(("GHSA-", "PYSEC-", "CVE-")):
        if vuln_id.startswith(prefix):
            return priority
    return 3


def record_severity(record: dict[str, Any]) -> tuple[Severity, float | None]:
    """Severity of one OSV record, plus the CVSS v3 base score when there is one."""
    score = None
    for entry in record.get("severity") or []:
        if entry.get("type") == "CVSS_V3":
            score = cvss3_base_score(entry.get("score", ""))
            if score is not None:
                break

    label = (record.get("database_specific") or {}).get("severity")
    if isinstance(label, str):
        try:
            return Severity.parse(label), score
        except ValueError:
            pass
    if score is not None:
        return severity_from_score(score), score
    return Severity.UNKNOWN, None


def severity_from_score(score: float) -> Severity:
    """CVSS v3 qualitative rating."""
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MODERATE
    return Severity.LOW


def fixed_versions(record: dict[str, Any], package: str) -> list[str]:
    """Every version listed as 'fixed' for this package in an OSV record."""
    wanted = canonicalize_name(package)
    found: list[str] = []
    for affected in record.get("affected") or []:
        info = affected.get("package") or {}
        if info.get("ecosystem") != "PyPI" or canonicalize_name(info.get("name", "")) != wanted:
            continue
        for version_range in affected.get("ranges") or []:
            if version_range.get("type") not in ("ECOSYSTEM", "SEMVER"):
                continue  # GIT ranges use commit hashes, not versions
            found.extend(e["fixed"] for e in version_range.get("events") or [] if "fixed" in e)
    return found


def pick_fix_version(installed: str, fixed: Iterable[str]) -> str | None:
    """The smallest fixed version newer than the installed one."""
    try:
        current = Version(installed)
    except InvalidVersion:
        return None
    candidates = []
    for value in fixed:
        try:
            if Version(value) > current:
                candidates.append(value)
        except InvalidVersion:
            continue
    return min(candidates, key=Version) if candidates else None


# --------------------------------------------------------------------------- CVSS v3

_CVSS3_WEIGHTS: dict[str, dict[str, float]] = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}
_CVSS3_PR = {"U": {"N": 0.85, "L": 0.62, "H": 0.27}, "C": {"N": 0.85, "L": 0.68, "H": 0.5}}


def cvss3_base_score(vector: str) -> float | None:
    """Base score of a CVSS v3.x vector such as ``CVSS:3.1/AV:N/AC:L/...``.

    Follows the formula in the CVSS v3.1 specification, section 7.1.
    """
    if not vector.startswith("CVSS:3."):
        return None
    metrics = dict(part.split(":", 1) for part in vector.split("/")[1:] if ":" in part)
    try:
        scope = metrics["S"]
        av, ac, ui = (_CVSS3_WEIGHTS[m][metrics[m]] for m in ("AV", "AC", "UI"))
        c, i, a = (_CVSS3_WEIGHTS[m][metrics[m]] for m in ("C", "I", "A"))
        pr = _CVSS3_PR[scope][metrics["PR"]]
    except KeyError:
        return None

    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    unchanged_scope = scope == "U"
    impact = 6.42 * iss if unchanged_scope else 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    if impact <= 0:
        return 0.0
    exploitability = 8.22 * av * ac * pr * ui
    if unchanged_scope:
        return _roundup(min(impact + exploitability, 10))
    return _roundup(min(1.08 * (impact + exploitability), 10))


def _roundup(value: float) -> float:
    """CVSS 'Roundup': smallest number with one decimal >= value, float-error safe."""
    integer = round(value * 100_000)
    if integer % 10_000 == 0:
        return integer / 100_000
    return (math.floor(integer / 10_000) + 1) / 10.0
