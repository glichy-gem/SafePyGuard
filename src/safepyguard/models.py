"""Data classes shared by every part of SafePyGuard."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from enum import Enum, IntEnum
from typing import Any

from packaging.version import InvalidVersion, Version


class Category(str, Enum):
    """Where a dependency's license lands under the active policy."""

    APPROVED = "approved"
    RESTRICTED = "restricted"
    DENIED = "denied"
    UNKNOWN = "unknown"

    @property
    def rank(self) -> int:
        """Lower is more permissive. Used to combine OR / AND license expressions."""
        return _CATEGORY_RANK[self]


_CATEGORY_RANK = {
    Category.APPROVED: 0,
    Category.RESTRICTED: 1,
    Category.UNKNOWN: 2,
    Category.DENIED: 3,
}


class Severity(IntEnum):
    """Vulnerability severity, ordered so comparisons work (HIGH > LOW)."""

    UNKNOWN = 0
    LOW = 1
    MODERATE = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str) -> Severity:
        name = value.strip().upper()
        if name == "MEDIUM":  # GHSA says MODERATE, CVSS says MEDIUM
            name = "MODERATE"
        try:
            return cls[name]
        except KeyError:
            raise ValueError(f"unknown severity: {value!r}") from None

    @property
    def label(self) -> str:
        return self.name.lower()


def version_key(version: str) -> Version:
    """Sort key for version strings; unparsable versions sort first."""
    try:
        return Version(version)
    except InvalidVersion:
        return Version("0")


@dataclass
class Dependency:
    """One line of a requirements file."""

    name: str
    specifier: str  # e.g. "==2.19.0", ">=1.0,<2" or "" for none
    version: str | None  # the exact version when pinned with == / ===
    source: str  # requirements file the line came from
    line: int
    marker: str | None = None

    @property
    def pinned(self) -> bool:
        return self.version is not None

    @property
    def location(self) -> str:
        return f"{self.source}:{self.line}"


@dataclass
class LicenseInfo:
    """What a package declares as its license and how the policy judged it."""

    category: Category = Category.UNKNOWN
    expression: str | None = None  # normalized SPDX expression, e.g. "MIT OR Apache-2.0"
    raw: str | None = None  # what the package actually declared
    source: str | None = None  # which metadata field the license came from
    note: str | None = None  # e.g. the reason for a policy exception

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category.value,
            "expression": self.expression,
            "raw": self.raw,
            "source": self.source,
            "note": self.note,
        }


@dataclass
class Vulnerability:
    """A known vulnerability affecting the scanned version of a package."""

    id: str
    summary: str
    severity: Severity
    score: float | None = None  # CVSS base score, when available
    aliases: list[str] = field(default_factory=list)
    fixed_versions: list[str] = field(default_factory=list)
    fix_version: str | None = None  # smallest fixed version above the scanned one
    url: str = ""

    @property
    def cves(self) -> list[str]:
        return [alias for alias in self.aliases if alias.startswith("CVE-")]

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "summary": self.summary,
            "severity": self.severity.label,
            "score": self.score,
            "aliases": self.aliases,
            "fixed_versions": self.fixed_versions,
            "fix_version": self.fix_version,
            "url": self.url,
        }


@dataclass
class PackageResult:
    """Everything SafePyGuard found out about one dependency."""

    dependency: Dependency
    version: str | None  # the version that was actually checked
    license: LicenseInfo = field(default_factory=LicenseInfo)
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def name(self) -> str:
        return self.dependency.name

    @property
    def worst_severity(self) -> Severity | None:
        return max((v.severity for v in self.vulnerabilities), default=None)

    @property
    def recommended_version(self) -> str | None:
        """Lowest version that fixes every known vulnerability that has a fix."""
        fixes = [v.fix_version for v in self.vulnerabilities if v.fix_version]
        return max(fixes, key=version_key) if fixes else None

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "requested": self.dependency.specifier,
            "version": self.version,
            "pinned": self.dependency.pinned,
            "location": self.dependency.location,
            "license": self.license.to_dict(),
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            "recommended_version": self.recommended_version,
            "errors": self.errors,
        }


@dataclass
class Report:
    """The result of one scan."""

    requirements: str
    policy: str
    packages: list[PackageResult] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    ignored_vulnerabilities: list[str] = field(default_factory=list)
    checked_licenses: bool = True
    checked_vulnerabilities: bool = True

    @property
    def vulnerable_packages(self) -> list[PackageResult]:
        return [p for p in self.packages if p.vulnerabilities]

    def license_counts(self) -> dict[str, int]:
        counts = Counter(p.license.category for p in self.packages)
        return {category.value: counts[category] for category in Category}

    def severity_counts(self) -> dict[str, int]:
        counts = Counter(v.severity for p in self.packages for v in p.vulnerabilities)
        return {severity.label: counts[severity] for severity in sorted(Severity, reverse=True)}

    def to_dict(self) -> dict[str, Any]:
        return {
            "requirements": self.requirements,
            "policy": self.policy,
            "checked": {
                "licenses": self.checked_licenses,
                "vulnerabilities": self.checked_vulnerabilities,
            },
            "summary": {
                "packages": len(self.packages),
                "licenses": self.license_counts(),
                "vulnerabilities": self.severity_counts(),
                "vulnerable_packages": len(self.vulnerable_packages),
            },
            "packages": [p.to_dict() for p in self.packages],
            "warnings": self.warnings,
            "ignored_vulnerabilities": self.ignored_vulnerabilities,
        }
