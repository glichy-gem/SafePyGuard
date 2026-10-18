"""Parse pip requirements files into Dependency objects."""

from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import Path

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name

from ..errors import RequirementsError
from ..models import Dependency

# A '#' starts a comment when it begins the line or follows whitespace (pip's rule).
_COMMENT = re.compile(r"(^|\s+)#.*$")
# Per-requirement options such as "--hash=sha256:..." that follow the requirement itself.
_TRAILING_OPTIONS = re.compile(r"\s+--?[A-Za-z]")
_INCLUDE_OPTIONS = ("-r", "--requirement")
_EDITABLE_OPTIONS = ("-e", "--editable")


def parse_requirements(path: str | Path) -> tuple[list[Dependency], list[str]]:
    """Read a requirements file (following ``-r`` includes).

    Returns the dependencies plus human-readable warnings for lines that were skipped.
    Raises RequirementsError when the top-level file can't be read.
    """
    dependencies: dict[str, Dependency] = {}
    warnings: list[str] = []
    _parse_file(Path(path), dependencies, warnings, seen=set())
    return list(dependencies.values()), warnings


def _parse_file(
    path: Path,
    dependencies: dict[str, Dependency],
    warnings: list[str],
    seen: set[Path],
) -> None:
    resolved = path.resolve()
    if resolved in seen:  # a.txt includes b.txt which includes a.txt
        return
    seen.add(resolved)

    try:
        text = path.read_text(encoding="utf-8-sig")
    except FileNotFoundError:
        raise RequirementsError(f"requirements file not found: {path}") from None
    except OSError as exc:
        raise RequirementsError(f"could not read {path}: {exc}") from exc

    for line_no, line in _logical_lines(text):
        where = f"{path}:{line_no}"

        if line.startswith("-"):
            option, value = _split_option(line)
            if option in _INCLUDE_OPTIONS:
                try:
                    _parse_file(path.parent / value, dependencies, warnings, seen)
                except RequirementsError as exc:
                    warnings.append(f"{where}: {exc}")
            elif option in _EDITABLE_OPTIONS:
                warnings.append(f"{where}: skipped editable requirement '{value}'")
            # Other options (--index-url, -c, --pre, ...) don't name a dependency.
            continue

        requirement_text = _TRAILING_OPTIONS.split(line, maxsplit=1)[0]
        try:
            requirement = Requirement(requirement_text)
        except InvalidRequirement as exc:
            warnings.append(f"{where}: could not parse '{line}' ({exc})")
            continue
        if requirement.url:
            warnings.append(f"{where}: skipped '{requirement.name}' (installed from a URL)")
            continue

        key = canonicalize_name(requirement.name)
        if key in dependencies:
            warnings.append(f"{where}: duplicate requirement '{requirement.name}' ignored")
            continue
        dependencies[key] = Dependency(
            name=requirement.name,
            specifier=str(requirement.specifier),
            version=_pinned_version(requirement),
            source=str(path),
            line=line_no,
            marker=str(requirement.marker) if requirement.marker else None,
        )


def _logical_lines(text: str) -> Iterator[tuple[int, str]]:
    """Yield (first line number, content) with comments removed and ``\\`` continuations joined."""
    buffer = ""
    start: int | None = None
    for number, raw in enumerate(text.splitlines(), start=1):
        line = _COMMENT.sub("", raw).rstrip()
        if start is None:
            start = number
        if line.endswith("\\"):
            buffer += line[:-1] + " "
            continue
        buffer = (buffer + line).strip()
        if buffer:
            yield start, buffer
        buffer, start = "", None
    if buffer.strip() and start is not None:
        yield start, buffer.strip()


def _split_option(line: str) -> tuple[str, str]:
    """Split '-r file', '-rfile', '--requirement file' or '--requirement=file'."""
    if line.startswith("--"):
        option, sep, value = line.partition("=")
        if not sep:
            option, _, value = line.partition(" ")
        return option.strip(), value.strip()
    return line[:2], line[2:].strip()


def _pinned_version(requirement: Requirement) -> str | None:
    """The exact version for 'pkg==1.2.3' / 'pkg===1.2.3'; None for anything looser."""
    specifiers = list(requirement.specifier)
    if len(specifiers) == 1:
        spec = specifiers[0]
        if spec.operator in ("==", "===") and "*" not in spec.version:
            return spec.version
    return None
