from __future__ import annotations

from pathlib import Path

import pytest

from safepyguard.errors import PolicyError
from safepyguard.licenses.normalize import parse_expression
from safepyguard.licenses.policy import (
    BUILTIN,
    Policy,
    default_policy_text,
    load_policy,
    parse_policy,
    parse_severity_threshold,
)
from safepyguard.models import Category, Severity


@pytest.fixture
def policy() -> Policy:
    return load_policy()


@pytest.mark.parametrize(
    ("expression", "expected"),
    [
        ("MIT", Category.APPROVED),
        ("GPL-3.0-only", Category.DENIED),
        ("AGPL-3.0-or-later", Category.DENIED),
        ("LGPL-2.1-only", Category.RESTRICTED),
        ("MPL-2.0", Category.RESTRICTED),
        ("WTFPL", Category.UNKNOWN),
        ("MIT OR GPL-3.0-only", Category.APPROVED),  # you may choose MIT
        ("MIT AND GPL-3.0-only", Category.DENIED),  # you must comply with both
        ("MPL-2.0 OR WTFPL", Category.RESTRICTED),
        ("MIT AND WTFPL", Category.UNKNOWN),
        ("GPL-3.0-only OR WTFPL", Category.UNKNOWN),
    ],
)
def test_classify(policy: Policy, expression: str, expected: Category) -> None:
    assert policy.classify(parse_expression(expression)) is expected


def test_classify_none_is_unknown(policy: Policy) -> None:
    assert policy.classify(None) is Category.UNKNOWN


def test_exact_entry_beats_wildcard() -> None:
    policy = parse_policy(
        """
        [licenses]
        approved = ["GPL-2.0-only"]
        denied = ["GPL-*"]
        """
    )
    assert policy.category_for("GPL-2.0-only") is Category.APPROVED
    assert policy.category_for("GPL-3.0-only") is Category.DENIED


def test_denied_beats_approved_at_equal_precision() -> None:
    policy = parse_policy('[licenses]\napproved = ["MIT"]\ndenied = ["mit"]\n')
    assert policy.category_for("MIT") is Category.DENIED


def test_builtin_policy_defaults(policy: Policy) -> None:
    assert policy.source == BUILTIN
    assert policy.fail_on_license == {Category.DENIED}
    assert policy.fail_on_severity is Severity.HIGH
    assert policy.ignore_vulnerabilities == []


def test_full_policy_file(tmp_path: Path) -> None:
    path = tmp_path / "policy.toml"
    path.write_text(
        """
        [licenses]
        approved = ["MIT"]

        [exceptions]
        "PyQt5" = { category = "approved", reason = "commercial license bought" }

        [vulnerabilities]
        ignore = ["GHSA-aaaa-bbbb-cccc"]

        [gate]
        fail_on_license = ["denied", "unknown"]
        fail_on_severity = "critical"
        """,
        encoding="utf-8",
    )
    policy = load_policy(path)
    assert policy.source == str(path)
    exception = policy.exception_for("pyqt5")
    assert exception is not None
    assert exception.category is Category.APPROVED
    assert exception.reason == "commercial license bought"
    assert policy.ignore_vulnerabilities == ["GHSA-aaaa-bbbb-cccc"]
    assert policy.fail_on_license == {Category.DENIED, Category.UNKNOWN}
    assert policy.fail_on_severity is Severity.CRITICAL


def test_fail_on_severity_none() -> None:
    assert parse_policy('[gate]\nfail_on_severity = "none"\n').fail_on_severity is None


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("[licenses\n", "invalid TOML"),
        ("[licence]\n", "unknown section"),
        ("[licenses]\napprove = []\n", "unknown key"),
        ("[licenses]\napproved = 'MIT'\n", "list of strings"),
        ("licenses = 1\n", "must be a table"),
        ('[exceptions]\npkg = "approved"\n', "must look like"),
        ('[exceptions]\npkg = { category = "ok" }\n', "category must be one of"),
        ('[gate]\nfail_on_license = ["bad"]\n', "category must be one of"),
        ('[gate]\nfail_on_severity = "severe"\n', "fail_on_severity"),
        ('[gate]\nfail_on_severity = "unknown"\n', "fail_on_severity"),
    ],
)
def test_invalid_policies(text: str, message: str) -> None:
    with pytest.raises(PolicyError, match=message):
        parse_policy(text)


def test_missing_policy_file(tmp_path: Path) -> None:
    with pytest.raises(PolicyError, match="not found"):
        load_policy(tmp_path / "missing.toml")


def test_default_policy_text_round_trips() -> None:
    assert parse_policy(default_policy_text()).approved == load_policy().approved


def test_parse_severity_threshold() -> None:
    assert parse_severity_threshold("HIGH") is Severity.HIGH
    assert parse_severity_threshold("medium") is Severity.MODERATE
    assert parse_severity_threshold(" none ") is None
