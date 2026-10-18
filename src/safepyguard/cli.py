"""Command-line interface: ``safepyguard scan`` and ``safepyguard init-policy``."""

from __future__ import annotations

import contextlib
from pathlib import Path

import click
from rich.console import Console

from ._version import __version__
from .errors import SafePyGuardError
from .gate import evaluate
from .licenses.policy import default_policy_text, load_policy, parse_severity_threshold
from .models import Category
from .reporters import FORMATS, render, render_table
from .scanner import scan as run_scan

EXIT_OK = 0  # everything passed the policy
EXIT_FAILED = 1  # the policy was violated
EXIT_ERROR = 2  # the scan itself could not run
DEFAULT_POLICY_FILE = "safepyguard.toml"


@click.group()
@click.version_option(__version__, prog_name="safepyguard")
def main() -> None:
    """SafePyGuard: license & vulnerability scanner for Python dependencies."""


@main.command()
@click.option(
    "-r",
    "--requirements",
    type=click.Path(dir_okay=False, path_type=Path),
    default="requirements.txt",
    show_default=True,
    help="Requirements file to scan.",
)
@click.option(
    "-p",
    "--policy",
    "policy_path",
    type=click.Path(dir_okay=False, path_type=Path),
    help=f"Policy TOML file. Defaults to ./{DEFAULT_POLICY_FILE} if present, "
    "otherwise the built-in policy.",
)
@click.option(
    "-f",
    "--format",
    "output_format",
    type=click.Choice(FORMATS),
    default="table",
    show_default=True,
    help="Report format.",
)
@click.option(
    "-o",
    "--output",
    type=click.Path(dir_okay=False, path_type=Path),
    help="Write the report to this file instead of the terminal.",
)
@click.option(
    "--fail-on-license",
    help="Comma-separated license categories that fail the scan "
    "(approved, restricted, denied, unknown) or 'none'. Overrides the policy.",
)
@click.option(
    "--fail-on-severity",
    type=click.Choice(["low", "moderate", "high", "critical", "none"], case_sensitive=False),
    help="Lowest vulnerability severity that fails the scan. Overrides the policy.",
)
@click.option(
    "--ignore-vuln",
    multiple=True,
    metavar="ID",
    help="Vulnerability id or alias to ignore (repeatable).",
)
@click.option("--no-licenses", is_flag=True, help="Skip the license check.")
@click.option("--no-vulns", is_flag=True, help="Skip the vulnerability check.")
@click.option("--no-cache", is_flag=True, help="Don't use or update the on-disk cache.")
@click.option(
    "--timeout",
    type=float,
    default=15.0,
    show_default=True,
    help="Network timeout in seconds.",
)
@click.pass_context
def scan(
    ctx: click.Context,
    requirements: Path,
    policy_path: Path | None,
    output_format: str,
    output: Path | None,
    fail_on_license: str | None,
    fail_on_severity: str | None,
    ignore_vuln: tuple[str, ...],
    no_licenses: bool,
    no_vulns: bool,
    no_cache: bool,
    timeout: float,
) -> None:
    """Scan a requirements file for license and vulnerability issues.

    Exit codes: 0 = passed, 1 = policy violated, 2 = the scan could not run.
    """
    license_gate = _parse_categories(fail_on_license) if fail_on_license is not None else None

    try:
        if policy_path is None and Path(DEFAULT_POLICY_FILE).is_file():
            policy_path = Path(DEFAULT_POLICY_FILE)
        policy = load_policy(policy_path)
        with _spinner(f"Scanning {requirements} ..."):
            report = run_scan(
                requirements,
                policy,
                licenses=not no_licenses,
                vulnerabilities=not no_vulns,
                ignore_vulnerabilities=ignore_vuln,
                cache=not no_cache,
                timeout=timeout,
            )
    except SafePyGuardError as exc:
        click.secho(f"error: {exc}", fg="red", err=True)
        ctx.exit(EXIT_ERROR)

    gate = evaluate(
        report,
        fail_on_license=license_gate if license_gate is not None else policy.fail_on_license,
        fail_on_severity=(
            parse_severity_threshold(fail_on_severity)
            if fail_on_severity is not None
            else policy.fail_on_severity
        ),
    )

    if output is not None:
        output.write_text(render(output_format, report, gate), encoding="utf-8")
        status = "PASSED" if gate.passed else "FAILED"
        click.echo(f"Report written to {output} ({status})", err=True)
    elif output_format == "table":
        render_table(report, gate, Console())
    else:
        click.echo(render(output_format, report, gate), nl=False)

    ctx.exit(EXIT_OK if gate.passed else EXIT_FAILED)


@main.command("init-policy")
@click.option(
    "--path",
    type=click.Path(dir_okay=False, path_type=Path),
    default=DEFAULT_POLICY_FILE,
    show_default=True,
    help="Where to write the policy file.",
)
@click.option("--force", is_flag=True, help="Overwrite an existing file.")
def init_policy(path: Path, force: bool) -> None:
    """Write the built-in policy to a file so you can edit it."""
    if path.exists() and not force:
        raise click.ClickException(f"{path} already exists (use --force to overwrite)")
    path.write_text(default_policy_text(), encoding="utf-8")
    click.echo(f"Wrote the default policy to {path}")


def _parse_categories(value: str) -> set[Category]:
    if value.strip().lower() == "none":
        return set()
    categories = set()
    for part in filter(None, (p.strip().lower() for p in value.split(","))):
        try:
            categories.add(Category(part))
        except ValueError:
            raise click.BadParameter(
                f"'{part}' is not one of approved, restricted, denied, unknown, none",
                param_hint="'--fail-on-license'",
            ) from None
    return categories


def _spinner(message: str) -> contextlib.AbstractContextManager[object]:
    """Show a spinner on stderr, but only when a human is watching."""
    console = Console(stderr=True)
    if console.is_terminal:
        return console.status(message)
    return contextlib.nullcontext()
