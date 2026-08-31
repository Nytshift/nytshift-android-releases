#!/usr/bin/env python3
"""Small deterministic secret/material scan for the intentionally public repository."""

from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SKIP_PARTS = {".git", "__pycache__", ".pytest_cache"}
BINARY_OR_KEY_SUFFIXES = {
    ".aab", ".apk", ".der", ".jks", ".key", ".keystore", ".p12", ".pem", ".pfx",
}
PATTERNS = {
    "private-key block": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "GitHub token": re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})\b"),
    "AWS access key": re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    "Slack token": re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b"),
    "generic assigned credential": re.compile(
        r"(?im)^\s*(?:password|passwd|secret|token|api[_-]?key|private[_-]?key)\s*[:=]\s*"
        r"['\"](?!\$\{\{|<|example|redacted|changeme)([^'\"\r\n]{12,})['\"]"
    ),
}


def main() -> int:
    findings: list[str] = []
    for path in ROOT.rglob("*"):
        if any(part in SKIP_PARTS for part in path.parts) or not path.is_file():
            continue
        relative = path.relative_to(ROOT)
        if path.is_symlink():
            findings.append(f"symlink: {relative}")
            continue
        if path.suffix.lower() in BINARY_OR_KEY_SUFFIXES:
            findings.append(f"forbidden key/build artifact: {relative}")
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeError, OSError):
            findings.append(f"non-UTF-8 or unreadable public file: {relative}")
            continue
        # The single large base64 value is a compressed, digest-checked copy of public Python.
        scan_text = re.sub(r"(?m)^\s*BOUNDARY_ZLIB_B64:\s*\S+\s*$", "", text)
        for label, pattern in PATTERNS.items():
            if pattern.search(scan_text):
                findings.append(f"{label}: {relative}")
    if findings:
        for finding in sorted(findings):
            print(f"secret scan finding: {finding}", file=sys.stderr)
        return 1
    print("secret scan passed: no key material or known credential form found")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
