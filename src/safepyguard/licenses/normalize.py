"""Turn the messy license strings found on PyPI into SPDX license expressions.

Packages declare licenses in three places, from most to least precise:

1. ``license_expression`` (PEP 639), e.g. ``"MIT OR Apache-2.0"``
2. ``license``, free text such as ``"Apache 2.0"`` or sometimes the whole license file
3. trove classifiers, e.g. ``"License :: OSI Approved :: BSD License"``
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# --------------------------------------------------------------------------- expression model


@dataclass(frozen=True)
class LicenseId:
    """A single SPDX license id, e.g. ``MIT``."""

    id: str

    def __str__(self) -> str:
        return self.id


@dataclass(frozen=True)
class LicenseOp:
    """``A OR B`` (you may pick either) or ``A AND B`` (you must comply with both)."""

    op: str  # "AND" | "OR"
    args: tuple[Expression, ...]

    def __str__(self) -> str:
        parts = [f"({arg})" if isinstance(arg, LicenseOp) else str(arg) for arg in self.args]
        return f" {self.op} ".join(parts)


Expression = LicenseId | LicenseOp

# --------------------------------------------------------------------------- alias table

# SPDX id -> spellings seen in the wild (and the last segment of trove classifiers).
_ALIASES: dict[str, tuple[str, ...]] = {
    "MIT": ("MIT", "MIT License", "The MIT License (MIT)", "Expat", "MIT/Expat"),
    "MIT-0": ("MIT-0", "MIT No Attribution", "MIT No Attribution License (MIT-0)"),
    "Apache-2.0": (
        "Apache-2.0",
        "Apache 2.0",
        "Apache 2",
        "Apache2",
        "Apache",
        "ASL 2.0",
        "Apache License",
        "Apache License 2.0",
        "Apache License, Version 2.0",
        "Apache Software License",
        "Apache Software License 2.0",
    ),
    "BSD-2-Clause": (
        "BSD-2-Clause",
        "BSD 2-Clause",
        "2-Clause BSD",
        "BSD-2",
        "Simplified BSD",
        "FreeBSD",
    ),
    "BSD-3-Clause": (
        # A bare "BSD" almost always means the 3-clause license on PyPI.
        "BSD-3-Clause",
        "BSD 3-Clause",
        "3-Clause BSD",
        "BSD-3",
        "BSD",
        "BSD License",
        "New BSD",
        "New BSD License",
        "Modified BSD",
        "Revised BSD",
    ),
    "0BSD": ("0BSD", "Zero-Clause BSD"),
    "ISC": ("ISC", "ISC License", "ISCL", "ISC License (ISCL)"),
    "PSF-2.0": (
        "PSF-2.0",
        "PSF",
        "PSFL",
        "PSF License",
        "Python Software Foundation License",
    ),
    "Python-2.0": ("Python-2.0", "Python 2.0", "Python License"),
    "MPL-1.1": ("MPL-1.1", "MPL 1.1", "Mozilla Public License 1.1 (MPL 1.1)"),
    "MPL-2.0": (
        "MPL-2.0",
        "MPL 2.0",
        "MPL2",
        "MPLv2",
        "MPLv2.0",
        "Mozilla Public License 2.0",
        "Mozilla Public License 2.0 (MPL 2.0)",
    ),
    "LGPL-2.0-only": (
        "LGPL-2.0-only",
        "LGPL-2.0",
        "LGPLv2",
        "GNU Lesser General Public License v2 (LGPLv2)",
    ),
    "LGPL-2.0-or-later": (
        "LGPL-2.0-or-later",
        "LGPL-2.0+",
        "LGPLv2+",
        "GNU Lesser General Public License v2 or later (LGPLv2+)",
        "GNU Library or Lesser General Public License (LGPL)",
    ),
    "LGPL-2.1-only": ("LGPL-2.1-only", "LGPL-2.1", "LGPLv2.1", "LGPL 2.1"),
    "LGPL-2.1-or-later": ("LGPL-2.1-or-later", "LGPL-2.1+", "LGPLv2.1+"),
    "LGPL-3.0-only": (
        "LGPL-3.0-only",
        "LGPL-3.0",
        "LGPLv3",
        "LGPL 3",
        "LGPL 3.0",
        "LGPL",
        "GNU LGPL",
        "GNU Lesser General Public License v3",
        "GNU Lesser General Public License v3 (LGPLv3)",
    ),
    "LGPL-3.0-or-later": (
        "LGPL-3.0-or-later",
        "LGPL-3.0+",
        "LGPLv3+",
        "GNU Lesser General Public License v3 or later (LGPLv3+)",
    ),
    "GPL-2.0-only": (
        "GPL-2.0-only",
        "GPL-2.0",
        "GPLv2",
        "GPL 2",
        "GPL 2.0",
        "GNU General Public License v2 (GPLv2)",
    ),
    "GPL-2.0-or-later": (
        "GPL-2.0-or-later",
        "GPL-2.0+",
        "GPLv2+",
        "GNU General Public License v2 or later (GPLv2+)",
    ),
    "GPL-3.0-only": (
        "GPL-3.0-only",
        "GPL-3.0",
        "GPLv3",
        "GPL 3",
        "GPL 3.0",
        "GPL",
        "GNU GPL",
        "GNU GPLv3",
        "GNU GPL v3",
        "GNU General Public License",
        "GNU General Public License (GPL)",
        "GNU General Public License v3",
        "GNU General Public License v3 (GPLv3)",
    ),
    "GPL-3.0-or-later": (
        "GPL-3.0-or-later",
        "GPL-3.0+",
        "GPLv3+",
        "GNU General Public License v3 or later (GPLv3+)",
    ),
    "AGPL-3.0-only": (
        "AGPL-3.0-only",
        "AGPL-3.0",
        "AGPLv3",
        "AGPL",
        "GNU AGPLv3",
        "GNU Affero General Public License v3",
    ),
    "AGPL-3.0-or-later": (
        "AGPL-3.0-or-later",
        "AGPL-3.0+",
        "AGPLv3+",
        "GNU Affero General Public License v3 or later (AGPLv3+)",
    ),
    "EPL-1.0": ("EPL-1.0", "EPL 1.0", "Eclipse Public License 1.0 (EPL-1.0)"),
    "EPL-2.0": ("EPL-2.0", "EPL 2.0", "Eclipse Public License 2.0 (EPL-2.0)"),
    "EUPL-1.2": ("EUPL-1.2", "European Union Public Licence 1.2 (EUPL 1.2)"),
    "AFL-3.0": ("AFL-3.0", "Academic Free License (AFL)"),
    "Artistic-2.0": ("Artistic-2.0", "Artistic 2.0", "Artistic License", "Artistic License 2.0"),
    "BSL-1.0": ("BSL-1.0", "Boost", "Boost Software License 1.0 (BSL-1.0)"),
    "CC0-1.0": (
        "CC0-1.0",
        "CC0",
        "CC0 1.0",
        "CC0 1.0 Universal (CC0 1.0) Public Domain Dedication",
    ),
    "HPND": ("HPND", "Historical Permission Notice and Disclaimer (HPND)"),
    "SSPL-1.0": ("SSPL-1.0", "SSPL", "Server Side Public License (SSPL)"),
    "Unlicense": ("Unlicense", "The Unlicense", "The Unlicense (Unlicense)"),
    "UPL-1.0": ("UPL-1.0", "Universal Permissive License (UPL)"),
    "Zlib": ("Zlib", "zlib/libpng", "zlib/libpng License"),
    "LicenseRef-Public-Domain": ("Public Domain", "Public-Domain"),
    "LicenseRef-Proprietary": ("Proprietary", "Other/Proprietary License", "Commercial"),
}

# Valid SPDX ids we accept verbatim even though no alias points at them.
_EXTRA_IDS = (
    "Apache-1.1",
    "BSD-3-Clause-Clear",
    "BSD-4-Clause",
    "BUSL-1.1",
    "CC-BY-4.0",
    "CC-BY-NC-4.0",
    "CC-BY-SA-4.0",
    "CDDL-1.0",
    "CDDL-1.1",
    "MIT-CMU",
    "NCSA",
    "OFL-1.1",
    "PostgreSQL",
    "Python-2.0.1",
    "Unicode-3.0",
    "WTFPL",
    "X11",
)

_STOP_WORDS = {"the", "license", "licence", "licensed", "version", "software", "under"}


def _key(text: str) -> str:
    """Squash a license name so that spelling variants compare equal.

    "Apache License, Version 2.0" and "apache 2.0" both become "apache2.0".
    """
    words = []
    for word in re.findall(r"[a-z0-9.+]+", text.lower()):
        if word in _STOP_WORDS:
            continue
        if re.fullmatch(r"v\d[\d.]*\+?", word):  # "v3" -> "3"
            word = word[1:]
        words.append(word.strip("."))
    return "".join(words)


_BY_KEY: dict[str, str] = {}
for _spdx, _names in _ALIASES.items():
    for _name in _names:
        _BY_KEY[_key(_name)] = _spdx

_KNOWN_IDS = {spdx.lower(): spdx for spdx in (*_ALIASES, *_EXTRA_IDS)}

# Phrases that identify a license when a package pastes the whole license text.
_TEXT_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = tuple(
    (spdx, re.compile(pattern, re.IGNORECASE | re.DOTALL))
    for spdx, pattern in (
        ("AGPL-3.0-only", r"GNU AFFERO GENERAL PUBLIC LICENSE"),
        ("LGPL-3.0-only", r"GNU LESSER GENERAL PUBLIC LICENSE\s+Version 3"),
        ("LGPL-2.1-only", r"GNU LESSER GENERAL PUBLIC LICENSE\s+Version 2\.1"),
        ("GPL-3.0-only", r"GNU GENERAL PUBLIC LICENSE\s+Version 3"),
        ("GPL-2.0-only", r"GNU GENERAL PUBLIC LICENSE\s+Version 2"),
        ("MPL-2.0", r"Mozilla Public License,?\s+(Version|v\.?)\s*2\.0"),
        ("Apache-2.0", r"Apache License,?\s+Version 2\.0"),
        ("MIT", r"Permission is hereby granted, free of charge"),
        ("BSD-3-Clause", r"Redistribution and use in source and binary forms.*Neither the name"),
        ("BSD-2-Clause", r"Redistribution and use in source and binary forms"),
        ("ISC", r"Permission to use, copy, modify, and(/or)? distribute this software"),
    )
)

# --------------------------------------------------------------------------- public helpers


def normalize_id(text: str) -> str | None:
    """Map one license name to its SPDX id, or None when we don't recognise it."""
    cleaned = text.strip().strip("\"'")
    if not cleaned:
        return None
    if cleaned.lower() in _KNOWN_IDS:
        return _KNOWN_IDS[cleaned.lower()]
    if cleaned.startswith("LicenseRef-"):
        return cleaned
    return _BY_KEY.get(_key(cleaned))


def parse_expression(text: str) -> Expression | None:
    """Parse an SPDX expression or a free-text license string. None if unrecognised."""
    text = text.strip()
    if not text:
        return None
    single = normalize_id(text)
    if single:
        return LicenseId(single)
    try:
        return _SpdxParser(text).parse()
    except ValueError:
        return _parse_free_text(text)


def classifier_to_spdx(classifier: str) -> str | None:
    """``"License :: OSI Approved :: MIT License"`` -> ``"MIT"``."""
    return normalize_id(classifier.split("::")[-1])


def detect_license_text(text: str) -> str | None:
    """Recognise a full license text pasted into the ``license`` field."""
    for spdx, pattern in _TEXT_PATTERNS:
        if pattern.search(text):
            return spdx
    return None


@dataclass
class ResolvedLicense:
    expression: Expression | None
    raw: str | None  # what the package declared, for display
    source: str | None  # "license_expression" | "license" | "classifiers" | "license_text"


def resolve_license(
    license_expression: str | None,
    license_text: str | None,
    classifiers: list[str],
) -> ResolvedLicense:
    """Pick the most precise license declaration that we can understand."""
    full_text = bool(license_text) and _looks_like_full_text(license_text or "")

    candidates = [("license_expression", license_expression)]
    if not full_text:
        candidates.append(("license", license_text))
    for source, raw in candidates:
        if raw:
            expression = parse_expression(raw)
            if expression is not None:
                return ResolvedLicense(expression, raw, source)

    license_classifiers = [c for c in classifiers if c.startswith("License ::")]
    ids = list(dict.fromkeys(i for i in map(classifier_to_spdx, license_classifiers) if i))
    if ids:
        # Several license classifiers conventionally mean "dual licensed": pick any.
        expression = _combine("OR", ids)
        raw = "; ".join(c.split("::")[-1].strip() for c in license_classifiers)
        return ResolvedLicense(expression, raw, "classifiers")

    if full_text and license_text:
        detected = detect_license_text(license_text)
        first_line = license_text.strip().splitlines()[0][:80]
        if detected:
            return ResolvedLicense(LicenseId(detected), first_line, "license_text")
        return ResolvedLicense(None, first_line, "license_text")

    raw = license_expression or license_text or ("; ".join(license_classifiers) or None)
    return ResolvedLicense(None, raw, None)


# --------------------------------------------------------------------------- internals


def _looks_like_full_text(text: str) -> bool:
    return "\n" in text.strip() or len(text) > 120


def _combine(op: str, ids: list[str]) -> Expression:
    if len(ids) == 1:
        return LicenseId(ids[0])
    return LicenseOp(op, tuple(LicenseId(i) for i in ids))


_OR_SPLIT = re.compile(r"\s*,?\s+or\s+|\s*/\s*", re.IGNORECASE)
_AND_SPLIT = re.compile(r"\s+and\s+", re.IGNORECASE)


def _parse_free_text(text: str) -> Expression | None:
    """Handle prose like "BSD or Apache License, Version 2.0"."""
    for op, pattern in (("OR", _OR_SPLIT), ("AND", _AND_SPLIT)):
        parts = [p for p in pattern.split(text) if p.strip()]
        if len(parts) > 1:
            ids = [normalize_id(p) for p in parts]
            if all(ids):
                return _combine(op, list(dict.fromkeys(i for i in ids if i)))
    return None


class _SpdxParser:
    """Recursive-descent parser for SPDX expressions (AND binds tighter than OR)."""

    def __init__(self, text: str) -> None:
        self.tokens: list[str] = re.findall(r"\(|\)|[^\s()]+", text)
        self.pos = 0

    def parse(self) -> Expression:
        expression = self._or()
        if self.pos != len(self.tokens):
            raise ValueError("unexpected trailing tokens")
        return expression

    def _peek(self) -> str | None:
        return self.tokens[self.pos].upper() if self.pos < len(self.tokens) else None

    def _next(self) -> str:
        if self.pos >= len(self.tokens):
            raise ValueError("unexpected end of expression")
        token = self.tokens[self.pos]
        self.pos += 1
        return token

    def _or(self) -> Expression:
        args = [self._and()]
        while self._peek() == "OR":
            self.pos += 1
            args.append(self._and())
        return args[0] if len(args) == 1 else LicenseOp("OR", tuple(args))

    def _and(self) -> Expression:
        args = [self._atom()]
        while self._peek() == "AND":
            self.pos += 1
            args.append(self._atom())
        return args[0] if len(args) == 1 else LicenseOp("AND", tuple(args))

    def _atom(self) -> Expression:
        token = self._next()
        if token == "(":
            expression = self._or()
            if self._next() != ")":
                raise ValueError("missing ')'")
            return expression
        if token == ")" or token.upper() in ("AND", "OR", "WITH"):
            raise ValueError(f"unexpected {token!r}")
        license_id = normalize_id(token)
        if license_id is None:
            raise ValueError(f"unknown license {token!r}")
        if self._peek() == "WITH":
            # "Apache-2.0 WITH LLVM-exception": the exception only grants extra
            # permissions, so the base license decides the category.
            self.pos += 1
            self._next()
        return LicenseId(license_id)
