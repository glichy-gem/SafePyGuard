from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

from safepyguard.errors import RequirementsError
from safepyguard.parsers.requirements import parse_requirements


def names(deps: list) -> list[str]:  # type: ignore[type-arg]
    return [d.name for d in deps]


def test_pinned_and_unpinned(write_requirements: Callable[..., Path]) -> None:
    path = write_requirements(
        """
        requests==2.19.0
        numpy>=1.20,<3
        flask
        pkg===1.0.post1
        wild==1.*
        """
    )
    deps, warnings = parse_requirements(path)
    assert warnings == []
    by_name = {d.name: d for d in deps}
    assert by_name["requests"].version == "2.19.0"
    assert by_name["requests"].pinned
    assert by_name["numpy"].version is None
    assert by_name["numpy"].specifier in ("<3,>=1.20", ">=1.20,<3")
    assert by_name["flask"].specifier == ""
    assert by_name["pkg"].version == "1.0.post1"
    assert by_name["wild"].version is None  # == with a wildcard is not a pin


def test_comments_blank_lines_and_line_numbers(write_requirements: Callable[..., Path]) -> None:
    path = write_requirements("# header\n\nrequests==2.19.0  # inline comment\n\nclick==8.1.7\n")
    deps, _ = parse_requirements(path)
    assert names(deps) == ["requests", "click"]
    assert [d.line for d in deps] == [3, 5]
    assert deps[0].location.endswith("requirements.txt:3")


def test_line_continuation_and_hashes(write_requirements: Callable[..., Path]) -> None:
    path = write_requirements(
        "requests==2.19.0 \\\n    --hash=sha256:abc \\\n    --hash=sha256:def\nclick==8.1.7\n"
    )
    deps, warnings = parse_requirements(path)
    assert warnings == []
    assert [(d.name, d.version, d.line) for d in deps] == [
        ("requests", "2.19.0", 1),
        ("click", "8.1.7", 4),
    ]


def test_markers_and_extras(write_requirements: Callable[..., Path]) -> None:
    path = write_requirements('pywin32==306; sys_platform == "win32"\nrequests[socks]==2.19.0\n')
    deps, _ = parse_requirements(path)
    assert deps[0].marker == 'sys_platform == "win32"'
    assert deps[1].name == "requests"
    assert deps[1].version == "2.19.0"


def test_includes_follow_and_stop_cycles(write_requirements: Callable[..., Path]) -> None:
    write_requirements("-r requirements.txt\nclick==8.1.7\n", name="base.txt")
    write_requirements("--requirement=missing.txt\n", name="other.txt")
    path = write_requirements("-r base.txt\n-rother.txt\nrequests==2.19.0\n")
    deps, warnings = parse_requirements(path)
    assert names(deps) == ["click", "requests"]
    assert len(warnings) == 1
    assert "missing.txt" in warnings[0]


def test_skipped_lines_produce_warnings(write_requirements: Callable[..., Path]) -> None:
    path = write_requirements(
        """
        --index-url https://example.com/simple
        -e .
        mypkg @ https://example.com/mypkg.zip
        this is not valid!!
        requests==2.19.0
        Requests==2.20.0
        """
    )
    deps, warnings = parse_requirements(path)
    assert names(deps) == ["requests"]
    joined = "\n".join(warnings)
    assert "editable" in joined
    assert "URL" in joined
    assert "could not parse" in joined
    assert "duplicate" in joined
    assert len(warnings) == 4


def test_missing_file(tmp_path: Path) -> None:
    with pytest.raises(RequirementsError, match="not found"):
        parse_requirements(tmp_path / "nope.txt")
