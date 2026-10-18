"""Output formats for a scan report."""

from __future__ import annotations

from collections.abc import Callable

from ..gate import GateResult
from ..models import Report
from .json_report import render_json
from .markdown import render_markdown
from .sarif import render_sarif
from .table import render_table, render_table_text

FORMATS = ("table", "json", "markdown", "sarif")

RENDERERS: dict[str, Callable[[Report, GateResult], str]] = {
    "table": render_table_text,
    "json": render_json,
    "markdown": render_markdown,
    "sarif": render_sarif,
}


def render(fmt: str, report: Report, gate: GateResult) -> str:
    return RENDERERS[fmt](report, gate)


__all__ = ["FORMATS", "RENDERERS", "render", "render_table"]
