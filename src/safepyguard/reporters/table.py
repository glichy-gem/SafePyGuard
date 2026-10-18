"""Human-friendly terminal report, built with rich."""

from __future__ import annotations

import io

from rich.console import Console
from rich.table import Table
from rich.text import Text

from ..gate import GateResult
from ..models import Category, PackageResult, Report, Severity

CATEGORY_STYLES = {
    Category.APPROVED: "green",
    Category.RESTRICTED: "yellow",
    Category.DENIED: "bold red",
    Category.UNKNOWN: "magenta",
}
SEVERITY_STYLES = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MODERATE: "yellow",
    Severity.LOW: "cyan",
    Severity.UNKNOWN: "magenta",
}


def render_table(report: Report, gate: GateResult, console: Console) -> None:
    table = Table(title=f"SafePyGuard: {report.requirements}", title_justify="left")
    table.add_column("Package", style="bold")
    table.add_column("Version")
    if report.checked_licenses:
        table.add_column("License")
        table.add_column("Category")
    if report.checked_vulnerabilities:
        table.add_column("Vulnerabilities")

    for package in report.packages:
        row = [Text(package.name), _version_cell(package)]
        if report.checked_licenses:
            category = package.license.category
            row.append(Text(package.license.expression or package.license.raw or "-"))
            row.append(Text(category.value.upper(), style=CATEGORY_STYLES[category]))
        if report.checked_vulnerabilities:
            row.append(_vulnerability_cell(package))
        table.add_row(*row)

    console.print(table)
    _print_details(report, console)
    _print_footer(report, gate, console)


def render_table_text(report: Report, gate: GateResult) -> str:
    """The table report as plain text (for writing to a file)."""
    buffer = io.StringIO()
    render_table(report, gate, Console(file=buffer, width=120, no_color=True, emoji=False))
    return buffer.getvalue()


def _version_cell(package: PackageResult) -> Text:
    text = Text(package.version or "?")
    if not package.dependency.pinned:
        text.append(" (unpinned)", style="dim")
    return text


def _vulnerability_cell(package: PackageResult) -> Text:
    worst = package.worst_severity
    if worst is None:
        if package.version is None:
            return Text("not checked", style="dim")
        return Text("none", style="green")
    text = Text(f"{len(package.vulnerabilities)} ({worst.name})", style=SEVERITY_STYLES[worst])
    if package.recommended_version:
        text.append(f" -> {package.recommended_version}", style="green")
    return text


def _print_details(report: Report, console: Console) -> None:
    vulnerable = report.vulnerable_packages
    if not vulnerable:
        return
    console.print()
    console.print(Text("Vulnerability details", style="bold underline"))
    for package in vulnerable:
        console.print(Text(f"{package.name} {package.version}", style="bold"))
        for vuln in package.vulnerabilities:
            ident = vuln.id + (f" ({', '.join(vuln.cves)})" if vuln.cves else "")
            fix = f"fixed in {vuln.fix_version}" if vuln.fix_version else "no fixed version"
            console.print(
                Text.assemble(
                    "  ",
                    (f"{vuln.severity.name:<9}", SEVERITY_STYLES[vuln.severity]),
                    f" {ident}  ",
                    (fix, "green" if vuln.fix_version else "dim"),
                )
            )
            console.print(Text(f"            {vuln.summary}", style="dim"))


def _print_footer(report: Report, gate: GateResult, console: Console) -> None:
    console.print()
    parts = [f"{len(report.packages)} package(s)"]
    if report.checked_licenses:
        counts = report.license_counts()
        parts.append("licenses: " + ", ".join(f"{n} {name}" for name, n in counts.items() if n))
    if report.checked_vulnerabilities:
        counts = report.severity_counts()
        total = sum(counts.values())
        detail = ", ".join(f"{n} {name}" for name, n in counts.items() if n)
        parts.append(f"vulnerabilities: {total}" + (f" ({detail})" if detail else ""))
    console.print(Text(" | ".join(parts)))
    console.print(Text(f"Policy: {report.policy}", style="dim"))

    for warning in report.warnings:
        console.print(Text(f"warning: {warning}", style="yellow"))
    for package in report.packages:
        for error in package.errors:
            console.print(Text(f"warning: {package.name}: {error}", style="yellow"))
    if report.ignored_vulnerabilities:
        ignored = ", ".join(report.ignored_vulnerabilities)
        console.print(Text(f"ignored by policy: {ignored}", style="dim"))

    if gate.passed:
        console.print(Text("PASSED", style="bold green"))
    else:
        console.print(Text("FAILED", style="bold red"))
        for reason in gate.reasons:
            console.print(Text(f"  - {reason}", style="red"))
