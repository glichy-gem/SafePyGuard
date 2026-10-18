"""License policy: which licenses are approved, restricted or denied, and what fails a scan."""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from importlib.resources import files
from pathlib import Path
from typing import Any

from packaging.utils import canonicalize_name

from ..errors import PolicyError
from ..models import Category, Severity
from .normalize import Expression, LicenseId

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover
    import tomli as tomllib

BUILTIN = "<built-in>"

_SECTIONS: dict[str, set[str]] = {
    "licenses": {"approved", "restricted", "denied"},
    "exceptions": set(),  # free-form: package names
    "vulnerabilities": {"ignore"},
    "gate": {"fail_on_license", "fail_on_severity"},
}


@dataclass
class PackageException:
    category: Category
    reason: str


@dataclass
class Policy:
    approved: list[str] = field(default_factory=list)
    restricted: list[str] = field(default_factory=list)
    denied: list[str] = field(default_factory=list)
    exceptions: dict[str, PackageException] = field(default_factory=dict)
    ignore_vulnerabilities: list[str] = field(default_factory=list)
    fail_on_license: set[Category] = field(default_factory=lambda: {Category.DENIED})
    fail_on_severity: Severity | None = Severity.HIGH
    source: str = BUILTIN

    def category_for(self, license_id: str) -> Category:
        """Category of one SPDX id.

        Exact entries beat wildcard entries; at equal precision denied beats
        restricted beats approved.
        """
        target = license_id.lower()
        ordered = (
            (Category.DENIED, self.denied),
            (Category.RESTRICTED, self.restricted),
            (Category.APPROVED, self.approved),
        )
        for wildcard in (False, True):
            for category, patterns in ordered:
                for pattern in patterns:
                    if _is_wildcard(pattern) == wildcard and fnmatchcase(target, pattern.lower()):
                        return category
        return Category.UNKNOWN

    def classify(self, expression: Expression | None) -> Category:
        """Category of a whole expression.

        ``A OR B`` lets you choose, so the most permissive option wins.
        ``A AND B`` binds you to both, so the strictest one wins.
        """
        if expression is None:
            return Category.UNKNOWN
        if isinstance(expression, LicenseId):
            return self.category_for(expression.id)
        categories = [self.classify(arg) for arg in expression.args]
        if expression.op == "OR":
            return min(categories, key=lambda c: c.rank)
        return max(categories, key=lambda c: c.rank)

    def exception_for(self, package: str) -> PackageException | None:
        return self.exceptions.get(canonicalize_name(package))


def default_policy_text() -> str:
    """The built-in policy, as written by ``safepyguard init-policy``."""
    resource = files("safepyguard.licenses").joinpath("default_policy.toml")
    return resource.read_text(encoding="utf-8")


def load_policy(path: str | Path | None = None) -> Policy:
    """Load a TOML policy file, or the built-in policy when ``path`` is None."""
    if path is None:
        return parse_policy(default_policy_text(), BUILTIN)
    path = Path(path)
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise PolicyError(f"policy file not found: {path}") from None
    except OSError as exc:
        raise PolicyError(f"could not read policy file {path}: {exc}") from exc
    return parse_policy(text, str(path))


def parse_policy(text: str, source: str = "<string>") -> Policy:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise PolicyError(f"{source}: invalid TOML: {exc}") from exc

    unknown = set(data) - set(_SECTIONS)
    if unknown:
        raise PolicyError(f"{source}: unknown section(s): {', '.join(sorted(unknown))}")

    policy = Policy(source=source)

    licenses = _section(data, "licenses", source)
    policy.approved = _str_list(licenses, "approved", source)
    policy.restricted = _str_list(licenses, "restricted", source)
    policy.denied = _str_list(licenses, "denied", source)

    for name, entry in _section(data, "exceptions", source).items():
        where = f'{source}: [exceptions] "{name}"'
        if not isinstance(entry, dict):
            raise PolicyError(f'{where} must look like {{ category = "approved", reason = "..." }}')
        policy.exceptions[canonicalize_name(name)] = PackageException(
            category=_category(entry.get("category"), where),
            reason=str(entry.get("reason", "")),
        )

    policy.ignore_vulnerabilities = _str_list(
        _section(data, "vulnerabilities", source), "ignore", source
    )

    gate = _section(data, "gate", source)
    if "fail_on_license" in gate:
        where = f"{source}: [gate] fail_on_license"
        policy.fail_on_license = {
            _category(value, where) for value in _str_list(gate, "fail_on_license", source)
        }
    if "fail_on_severity" in gate:
        try:
            policy.fail_on_severity = parse_severity_threshold(str(gate["fail_on_severity"]))
        except ValueError as exc:
            raise PolicyError(f"{source}: [gate] fail_on_severity: {exc}") from None
    return policy


def parse_severity_threshold(value: str) -> Severity | None:
    """``"high"`` -> Severity.HIGH, ``"none"`` -> None (never fail on vulnerabilities)."""
    if value.strip().lower() == "none":
        return None
    severity = Severity.parse(value)
    if severity is Severity.UNKNOWN:
        raise ValueError("use low, moderate, high, critical or none")
    return severity


def _is_wildcard(pattern: str) -> bool:
    return any(ch in pattern for ch in "*?[")


def _section(data: dict[str, Any], name: str, source: str) -> dict[str, Any]:
    section = data.get(name, {})
    if not isinstance(section, dict):
        raise PolicyError(f"{source}: [{name}] must be a table")
    allowed = _SECTIONS[name]
    if allowed:
        unknown = set(section) - allowed
        if unknown:
            raise PolicyError(f"{source}: unknown key(s) in [{name}]: {', '.join(sorted(unknown))}")
    return section


def _str_list(section: dict[str, Any], key: str, source: str) -> list[str]:
    value = section.get(key, [])
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise PolicyError(f"{source}: '{key}' must be a list of strings")
    return list(value)


def _category(value: Any, where: str) -> Category:
    try:
        return Category(str(value).lower())
    except ValueError:
        choices = ", ".join(c.value for c in Category)
        raise PolicyError(f"{where}: category must be one of {choices}, got {value!r}") from None
