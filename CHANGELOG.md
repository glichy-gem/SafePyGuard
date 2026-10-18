# Changelog

## 0.1.0 (2026-10-19)

First release.

- License scanning: reads `requirements.txt` (with `-r` includes, hashes, markers),
  fetches license metadata from PyPI and normalizes it to SPDX expressions using
  PEP 639 `license_expression`, the `license` field, trove classifiers or pasted license text.
- TOML license policy with Approved / Restricted / Denied / Unknown categories,
  wildcards, `OR` / `AND` handling and per-package exceptions.
- Vulnerability scanning via the OSV.dev batch API, with GHSA/PYSEC/CVE de-duplication,
  severity from GitHub advisories or CVSS v3, and the lowest fixed version.
- One unified report as a terminal table, JSON, Markdown or SARIF.
- CI gate with exit codes 0 / 1 / 2 and `--fail-on-license` / `--fail-on-severity`.
- On-disk cache (24h), concurrent lookups, GitHub Action and pre-commit hook.
