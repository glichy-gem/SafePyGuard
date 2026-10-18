"""Exceptions raised by SafePyGuard."""


class SafePyGuardError(Exception):
    """Base class for every error SafePyGuard raises on purpose."""


class RequirementsError(SafePyGuardError):
    """The requirements file is missing or unreadable."""


class PolicyError(SafePyGuardError):
    """The policy file is missing or invalid."""


class SourceError(SafePyGuardError):
    """PyPI or OSV could not be reached or returned something unexpected."""


class PackageNotFoundError(SourceError):
    """The package (or the requested version) does not exist on PyPI."""
