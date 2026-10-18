from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

import pytest
from click.testing import CliRunner

from fakes import FakeAPI
from safepyguard import __version__
from safepyguard.cli import EXIT_ERROR, EXIT_FAILED, EXIT_OK, main

pytestmark = pytest.mark.usefixtures("use_fake_network")


@pytest.fixture
def run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Callable[..., object]:
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()

    def invoke(*args: str):  # type: ignore[no-untyped-def]
        return runner.invoke(main, list(args), catch_exceptions=False)

    return invoke


@pytest.fixture
def demo(write_requirements: Callable[..., Path]) -> Path:
    return write_requirements("requests==2.19.0\nPyQt5==5.15.0\nnumpy\n")


def test_version(run) -> None:  # type: ignore[no-untyped-def]
    result = run("--version")
    assert __version__ in result.output


def test_failing_scan_exits_1(run, demo: Path) -> None:  # type: ignore[no-untyped-def]
    result = run("scan", "-r", str(demo), "--no-cache")
    assert result.exit_code == EXIT_FAILED
    assert "FAILED" in result.output
    assert "denied license: PyQt5" in result.output


def test_overrides_can_make_it_pass(run, demo: Path) -> None:  # type: ignore[no-untyped-def]
    result = run(
        "scan",
        "-r",
        str(demo),
        "--no-cache",
        "--fail-on-license",
        "none",
        "--fail-on-severity",
        "none",
    )
    assert result.exit_code == EXIT_OK
    assert "PASSED" in result.output


def test_ignore_vuln_and_partial_overrides(run, demo: Path) -> None:  # type: ignore[no-untyped-def]
    result = run(
        "scan",
        "-r",
        str(demo),
        "--no-cache",
        "--fail-on-license",
        "restricted,unknown",
        "--ignore-vuln",
        "CVE-2018-18074",
    )
    assert result.exit_code == EXIT_OK


def test_json_to_file(run, demo: Path, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    out = tmp_path / "report.json"
    result = run("scan", "-r", str(demo), "--no-cache", "-f", "json", "-o", str(out))
    assert result.exit_code == EXIT_FAILED
    assert f"Report written to {out} (FAILED)" in result.output
    data = json.loads(out.read_text(encoding="utf-8"))
    assert [p["name"] for p in data["packages"]] == ["requests", "PyQt5", "numpy"]


def test_markdown_to_stdout(run, demo: Path) -> None:  # type: ignore[no-untyped-def]
    result = run("scan", "-r", str(demo), "--no-cache", "-f", "markdown", "--no-vulns")
    assert result.exit_code == EXIT_FAILED
    assert result.output.startswith("## SafePyGuard report")


def test_table_to_file(run, demo: Path, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    out = tmp_path / "report.txt"
    run("scan", "-r", str(demo), "--no-cache", "-o", str(out))
    assert "Vulnerability details" in out.read_text(encoding="utf-8")


def test_missing_requirements_exits_2(run) -> None:  # type: ignore[no-untyped-def]
    result = run("scan", "-r", "nope.txt")
    assert result.exit_code == EXIT_ERROR
    assert "requirements file not found" in result.output


def test_bad_fail_on_license_exits_2(run, demo: Path) -> None:  # type: ignore[no-untyped-def]
    result = run("scan", "-r", str(demo), "--fail-on-license", "denied,nasty")
    assert result.exit_code == 2
    assert "'nasty' is not one of" in result.output


def test_network_failure_exits_2(  # type: ignore[no-untyped-def]
    run, demo: Path, use_fake_network: FakeAPI
) -> None:
    use_fake_network.down_hosts.add("api.osv.dev")
    result = run("scan", "-r", str(demo), "--no-cache")
    assert result.exit_code == EXIT_ERROR
    assert "could not reach OSV" in result.output


def test_init_policy_and_auto_discovery(run, demo: Path, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    result = run("init-policy")
    assert result.exit_code == 0
    policy = tmp_path / "safepyguard.toml"
    assert policy.exists()

    assert run("init-policy").exit_code == 1  # refuses to overwrite
    assert run("init-policy", "--force").exit_code == 0

    text = policy.read_text(encoding="utf-8")
    text = text.replace('fail_on_severity = "high"', 'fail_on_severity = "none"')
    text = text.replace(
        "[exceptions]", '[exceptions]\npyqt5 = { category = "approved", reason = "ok" }'
    )
    policy.write_text(text, encoding="utf-8")

    result = run("scan", "-r", str(demo), "--no-cache")
    assert result.exit_code == EXIT_OK
    assert "safepyguard.toml" in result.output


def test_invalid_policy_exits_2(run, demo: Path, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    bad = tmp_path / "bad.toml"
    bad.write_text("[nope]\n", encoding="utf-8")
    result = run("scan", "-r", str(demo), "--policy", str(bad))
    assert result.exit_code == EXIT_ERROR
    assert "unknown section" in result.output
