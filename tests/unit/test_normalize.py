from __future__ import annotations

import pytest

from safepyguard.licenses.normalize import (
    _ALIASES,
    LicenseId,
    LicenseOp,
    _key,
    classifier_to_spdx,
    detect_license_text,
    normalize_id,
    parse_expression,
    resolve_license,
)


def test_alias_table_has_no_conflicting_keys() -> None:
    seen: dict[str, str] = {}
    for spdx, aliases in _ALIASES.items():
        for alias in aliases:
            key = _key(alias)
            assert seen.setdefault(key, spdx) == spdx, f"{alias!r} maps to {spdx} and {seen[key]}"


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("MIT", "MIT"),
        ("mit", "MIT"),
        ("MIT License", "MIT"),
        ("The MIT License (MIT)", "MIT"),
        ("Apache 2.0", "Apache-2.0"),
        ("Apache License, Version 2.0", "Apache-2.0"),
        ("Apache Software License", "Apache-2.0"),
        ("apache-2.0", "Apache-2.0"),
        ("BSD", "BSD-3-Clause"),
        ("BSD License", "BSD-3-Clause"),
        ("BSD 2-Clause", "BSD-2-Clause"),
        ("GPLv3", "GPL-3.0-only"),
        ("GPL v3", "GPL-3.0-only"),
        ("GPLv3+", "GPL-3.0-or-later"),
        ("LGPL-2.1+", "LGPL-2.1-or-later"),
        ("Python Software Foundation License", "PSF-2.0"),
        ("MPL 2.0", "MPL-2.0"),
        ("WTFPL", "WTFPL"),
        ("LicenseRef-Internal", "LicenseRef-Internal"),
        ("Public Domain", "LicenseRef-Public-Domain"),
        ("Dual License", None),
        ("UNKNOWN", None),
        ("", None),
    ],
)
def test_normalize_id(text: str, expected: str | None) -> None:
    assert normalize_id(text) == expected


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("MIT OR Apache-2.0", "MIT OR Apache-2.0"),
        ("MIT AND (Apache-2.0 OR BSD-3-Clause)", "MIT AND (Apache-2.0 OR BSD-3-Clause)"),
        ("mit or apache-2.0 and isc", "MIT OR (Apache-2.0 AND ISC)"),
        ("Apache-2.0 WITH LLVM-exception", "Apache-2.0"),
        ("BSD or Apache License, Version 2.0", "BSD-3-Clause OR Apache-2.0"),
        ("MIT/Apache-2.0", "MIT OR Apache-2.0"),
        ("MIT and ISC", "MIT AND ISC"),
        ("MIT OR", None),
        ("MIT AND (", None),
        ("MIT OR Frobnicate", None),
    ],
)
def test_parse_expression(text: str, expected: str | None) -> None:
    result = parse_expression(text)
    assert (str(result) if result else None) == expected


def test_expression_structure() -> None:
    expr = parse_expression("MIT OR Apache-2.0 AND ISC")
    assert expr == LicenseOp(
        "OR", (LicenseId("MIT"), LicenseOp("AND", (LicenseId("Apache-2.0"), LicenseId("ISC"))))
    )


def test_classifier_to_spdx() -> None:
    assert classifier_to_spdx("License :: OSI Approved :: MIT License") == "MIT"
    assert classifier_to_spdx("License :: OSI Approved :: BSD License") == "BSD-3-Clause"
    assert (
        classifier_to_spdx("License :: OSI Approved :: GNU General Public License v2 (GPLv2)")
        == "GPL-2.0-only"
    )
    assert classifier_to_spdx("License :: OSI Approved") is None


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("MIT License\n\nPermission is hereby granted, free of charge, to any person", "MIT"),
        ("Apache License\n  Version 2.0, January 2004", "Apache-2.0"),
        ("                Apache License, Version 2.0\n...", "Apache-2.0"),
        ("Redistribution and use in source and binary forms ... Neither the name", "BSD-3-Clause"),
        ("Redistribution and use in source and binary forms, with or without", "BSD-2-Clause"),
        ("GNU LESSER GENERAL PUBLIC LICENSE\n Version 3, 29 June 2007", "LGPL-3.0-only"),
        ("GNU GENERAL PUBLIC LICENSE\n Version 2, June 1991", "GPL-2.0-only"),
        ("All rights reserved.", None),
    ],
)
def test_detect_license_text(text: str, expected: str | None) -> None:
    assert detect_license_text(text) == expected


class TestResolveLicense:
    def test_license_expression_wins(self) -> None:
        resolved = resolve_license("MIT", "BSD", ["License :: OSI Approved :: BSD License"])
        assert str(resolved.expression) == "MIT"
        assert resolved.source == "license_expression"

    def test_license_field_before_classifiers(self) -> None:
        resolved = resolve_license(None, "BSD-2-Clause", ["License :: OSI Approved :: BSD License"])
        assert str(resolved.expression) == "BSD-2-Clause"
        assert resolved.source == "license"

    def test_unparsable_field_falls_back_to_classifiers(self) -> None:
        classifiers = [
            "Programming Language :: Python",
            "License :: OSI Approved :: Apache Software License",
            "License :: OSI Approved :: BSD License",
        ]
        resolved = resolve_license(None, "Dual License", classifiers)
        assert str(resolved.expression) == "Apache-2.0 OR BSD-3-Clause"
        assert resolved.source == "classifiers"
        assert resolved.raw == "Apache Software License; BSD License"

    def test_full_license_text(self) -> None:
        text = "Copyright (c) 2020 Someone\n\nPermission is hereby granted, free of charge, ..."
        resolved = resolve_license(None, text, [])
        assert str(resolved.expression) == "MIT"
        assert resolved.source == "license_text"
        assert resolved.raw == "Copyright (c) 2020 Someone"

    def test_unrecognised_full_text(self) -> None:
        resolved = resolve_license(None, "Custom terms\nDo whatever, but ask first.", [])
        assert resolved.expression is None
        assert resolved.raw == "Custom terms"

    def test_nothing_declared(self) -> None:
        resolved = resolve_license(None, None, [])
        assert resolved.expression is None
        assert resolved.raw is None

    def test_unknown_short_text_is_kept_as_raw(self) -> None:
        resolved = resolve_license(None, "Some custom terms", [])
        assert resolved.expression is None
        assert resolved.raw == "Some custom terms"
