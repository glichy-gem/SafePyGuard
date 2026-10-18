"""Machine-readable JSON report."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from .._version import __version__
from ..gate import GateResult
from ..models import Report


def render_json(report: Report, gate: GateResult) -> str:
    data = {
        "tool": {"name": "safepyguard", "version": __version__},
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "gate": gate.to_dict(),
        **report.to_dict(),
    }
    return json.dumps(data, indent=2)
