"""Ties everything together: requirements -> PyPI -> license policy -> OSV -> Report."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import TypeVar

import httpx

from .cache import JsonCache
from .errors import PackageNotFoundError
from .licenses.normalize import ResolvedLicense, resolve_license
from .licenses.policy import Policy, load_policy
from .models import LicenseInfo, PackageResult, Report
from .parsers.requirements import parse_requirements
from .sources.http import make_client
from .sources.osv import OSVClient, build_vulnerabilities
from .sources.pypi import PyPIClient

T = TypeVar("T")
R = TypeVar("R")


def scan(
    requirements: str | Path,
    policy: Policy | str | Path | None = None,
    *,
    licenses: bool = True,
    vulnerabilities: bool = True,
    ignore_vulnerabilities: Iterable[str] = (),
    cache: bool = True,
    cache_dir: str | Path | None = None,
    timeout: float = 15.0,
    max_workers: int = 8,
    client: httpx.Client | None = None,
) -> Report:
    """Scan a requirements file and return a Report.

    ``policy`` is a Policy, a path to a TOML policy file, or None for the built-in policy.

    A package that doesn't exist on PyPI is recorded as an error on that package.
    Anything that stops the scan from being trustworthy (unreadable files, PyPI or OSV
    unreachable) raises a SafePyGuardError subclass instead.
    """
    active = policy if isinstance(policy, Policy) else load_policy(policy)
    dependencies, warnings = parse_requirements(requirements)
    results = [PackageResult(dependency=dep, version=dep.version) for dep in dependencies]
    json_cache = JsonCache(cache_dir, enabled=cache)
    http = client or make_client(timeout)
    ignored: list[str] = []
    try:
        # Unpinned requirements need PyPI to find out which version to check.
        if licenses or any(not r.dependency.pinned for r in results):
            pypi = PyPIClient(http, json_cache)
            _parallel(lambda r: _check_license(r, pypi, active, licenses), results, max_workers)
        if vulnerabilities:
            ignore = {i.upper() for i in (*active.ignore_vulnerabilities, *ignore_vulnerabilities)}
            osv = OSVClient(http, json_cache)
            ignored = _check_vulnerabilities(results, osv, ignore, max_workers)
    finally:
        if client is None:
            http.close()

    return Report(
        requirements=str(requirements),
        policy=active.source,
        packages=results,
        warnings=warnings,
        ignored_vulnerabilities=ignored,
        checked_licenses=licenses,
        checked_vulnerabilities=vulnerabilities,
    )


def _check_license(result: PackageResult, pypi: PyPIClient, policy: Policy, check: bool) -> None:
    dep = result.dependency
    meta = None
    try:
        result.version = dep.version or pypi.resolve_version(dep.name, dep.specifier)
        if check:
            meta = pypi.get_metadata(dep.name, result.version)
    except PackageNotFoundError as exc:
        result.errors.append(str(exc))
    if not check:
        return

    if meta is not None:
        resolved = resolve_license(meta.license_expression, meta.license, meta.classifiers)
    else:
        resolved = ResolvedLicense(None, None, None)
    info = LicenseInfo(
        category=policy.classify(resolved.expression),
        expression=str(resolved.expression) if resolved.expression is not None else None,
        raw=resolved.raw,
        source=resolved.source,
    )
    exception = policy.exception_for(dep.name)
    if exception is not None:
        info.category = exception.category
        info.note = "policy exception" + (f": {exception.reason}" if exception.reason else "")
    result.license = info


def _check_vulnerabilities(
    results: list[PackageResult], osv: OSVClient, ignore: set[str], max_workers: int
) -> list[str]:
    targets: list[tuple[PackageResult, str]] = []
    for result in results:
        if result.version is None:
            result.errors.append("vulnerabilities not checked: version unknown")
        else:
            targets.append((result, result.version))

    hits = osv.query_batch([(r.dependency.name, version) for r, version in targets])
    unique_ids = sorted({vuln_id for ids in hits for vuln_id in ids})
    fetched = _parallel(osv.get_vulnerability, unique_ids, max_workers)
    records = dict(zip(unique_ids, fetched, strict=True))

    ignored = []
    for (result, version), ids in zip(targets, hits, strict=True):
        found = build_vulnerabilities([records[i] for i in ids], result.dependency.name, version)
        for vuln in found:
            if {vuln.id.upper(), *(a.upper() for a in vuln.aliases)} & ignore:
                ignored.append(f"{result.name} {version}: {vuln.id}")
            else:
                result.vulnerabilities.append(vuln)
    return ignored


def _parallel(func: Callable[[T], R], items: Sequence[T], max_workers: int) -> list[R]:
    """Run ``func`` over ``items`` on a thread pool; network calls spend most time waiting."""
    if len(items) <= 1 or max_workers <= 1:
        return [func(item) for item in items]
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        return list(pool.map(func, items))
