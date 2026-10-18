"""Client for the PyPI JSON API (https://docs.pypi.org/api/json/)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import httpx
from packaging.specifiers import SpecifierSet
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

from ..cache import JsonCache
from ..errors import PackageNotFoundError, SourceError

PYPI_URL = "https://pypi.org/pypi"
_INFO_FIELDS = ("name", "version", "license", "license_expression", "classifiers")


@dataclass
class PackageMetadata:
    """The parts of a release's metadata that SafePyGuard needs."""

    name: str
    version: str
    license: str | None = None
    license_expression: str | None = None
    classifiers: list[str] = field(default_factory=list)


class PyPIClient:
    def __init__(
        self,
        client: httpx.Client,
        cache: JsonCache | None = None,
        base_url: str = PYPI_URL,
    ) -> None:
        self.client = client
        self.cache = cache or JsonCache(enabled=False)
        self.base_url = base_url.rstrip("/")

    def get_metadata(self, name: str, version: str) -> PackageMetadata:
        """Metadata of one exact release."""
        key = _info_key(name, version)
        info = self.cache.get(key)
        if info is None:
            info = _slim_info(self._get_json(f"{name}/{version}/json", f"{name}=={version}"))
            self.cache.set(key, info)
        return PackageMetadata(
            name=info.get("name") or name,
            version=info.get("version") or version,
            license=info.get("license") or None,
            license_expression=info.get("license_expression") or None,
            classifiers=list(info.get("classifiers") or []),
        )

    def resolve_version(self, name: str, specifier: str = "") -> str:
        """Newest non-yanked release matching ``specifier``.

        Pre-releases are only picked when nothing else matches (packaging's default).
        """
        matches = list(SpecifierSet(specifier).filter(self._releases(name)))
        if not matches:
            raise PackageNotFoundError(f"no release of {name} on PyPI matches '{specifier or '*'}'")
        return max(matches, key=Version)

    def _releases(self, name: str) -> list[str]:
        key = f"pypi:releases:{canonicalize_name(name)}"
        releases = self.cache.get(key)
        if releases is None:
            data = self._get_json(f"{name}/json", name)
            releases = []
            for version, files in (data.get("releases") or {}).items():
                if not files or all(f.get("yanked") for f in files):
                    continue
                try:
                    Version(version)
                except InvalidVersion:
                    continue
                releases.append(version)
            self.cache.set(key, releases)
            # The project page also carries the latest release's metadata; keep it.
            info = _slim_info(data)
            if info.get("version"):
                self.cache.set(_info_key(name, info["version"]), info)
        return list(releases)

    def _get_json(self, path: str, label: str) -> dict[str, Any]:
        try:
            response = self.client.get(f"{self.base_url}/{path}")
        except httpx.HTTPError as exc:
            raise SourceError(f"could not reach PyPI for {label}: {exc}") from exc
        if response.status_code == 404:
            raise PackageNotFoundError(f"{label} was not found on PyPI")
        if response.is_error:
            raise SourceError(f"PyPI returned HTTP {response.status_code} for {label}")
        try:
            data = response.json()
        except ValueError as exc:
            raise SourceError(f"PyPI returned invalid JSON for {label}") from exc
        if not isinstance(data, dict):
            raise SourceError(f"PyPI returned unexpected data for {label}")
        return data


def _info_key(name: str, version: str) -> str:
    return f"pypi:info:{canonicalize_name(name)}:{version}"


def _slim_info(data: dict[str, Any]) -> dict[str, Any]:
    info = data.get("info") or {}
    return {name: info.get(name) for name in _INFO_FIELDS}
