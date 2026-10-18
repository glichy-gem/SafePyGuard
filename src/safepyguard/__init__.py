"""SafePyGuard: license and vulnerability scanner for Python dependencies.

Typical use::

    from safepyguard import evaluate, scan

    report = scan("requirements.txt")          # or scan(..., policy="safepyguard.toml")
    gate = evaluate(report)
    print(gate.passed, gate.reasons)
"""

from ._version import __version__
from .errors import (
    PackageNotFoundError,
    PolicyError,
    RequirementsError,
    SafePyGuardError,
    SourceError,
)
from .gate import GateResult, evaluate
from .licenses.policy import Policy, load_policy
from .models import (
    Category,
    Dependency,
    LicenseInfo,
    PackageResult,
    Report,
    Severity,
    Vulnerability,
)
from .scanner import scan

__all__ = [
    "Category",
    "Dependency",
    "GateResult",
    "LicenseInfo",
    "PackageNotFoundError",
    "PackageResult",
    "Policy",
    "PolicyError",
    "Report",
    "RequirementsError",
    "SafePyGuardError",
    "Severity",
    "SourceError",
    "Vulnerability",
    "__version__",
    "evaluate",
    "load_policy",
    "scan",
]
