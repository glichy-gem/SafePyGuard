"""Markdown report, handy as a pull-request comment or a CI job summary."""

from __future__ import annotations

from ..gate import GateResult
from ..models import Report


def _cell(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def render_markdown(report: Report, gate: GateResult) -> str:
    lines = ["## SafePyGuard report", ""]
    lines.append(f"**Result: {'PASSED' if gate.passed else 'FAILED'}**")
    lines += [f"- {reason}" for reason in gate.reasons]
    lines += ["", f"Scanned `{report.requirements}` with policy `{report.policy}`.", ""]

    header = ["Package", "Version"]
    if report.checked_licenses:
        header += ["License", "Category"]
    if report.checked_vulnerabilities:
        header += ["Vulnerabilities"]
    lines.append("| " + " | ".join(header) + " |")
    lines.append("|" + "---|" * len(header))

    for package in report.packages:
        version = package.version or "?"
        if not package.dependency.pinned:
            version += " (unpinned)"
        row = [package.name, version]
        if report.checked_licenses:
            row += [
                package.license.expression or package.license.raw or "-",
                package.license.category.value,
            ]
        if report.checked_vulnerabilities:
            worst = package.worst_severity
            if worst is None:
                row.append("none" if package.version else "not checked")
            else:
                cell = f"{len(package.vulnerabilities)} (worst: {worst.label})"
                if package.recommended_version:
                    cell += f", upgrade to {package.recommended_version}"
                row.append(cell)
        lines.append("| " + " | ".join(_cell(c) for c in row) + " |")

    if report.vulnerable_packages:
        lines += ["", "### Vulnerabilities", ""]
        for package in report.vulnerable_packages:
            for vuln in package.vulnerabilities:
                aliases = f" ({', '.join(vuln.cves)})" if vuln.cves else ""
                fix = f"fixed in {vuln.fix_version}" if vuln.fix_version else "no fixed version"
                lines.append(
                    f"- **{package.name} {package.version}**: [{vuln.id}]({vuln.url}){aliases}, "
                    f"{vuln.severity.label}, {fix}. {_cell(vuln.summary)}"
                )

    notes = list(report.warnings)
    notes += [f"{p.name}: {e}" for p in report.packages for e in p.errors]
    notes += [f"ignored: {i}" for i in report.ignored_vulnerabilities]
    if notes:
        lines += ["", "### Notes", ""] + [f"- {_cell(n)}" for n in notes]
    return "\n".join(lines) + "\n"
