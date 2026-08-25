#!/usr/bin/env python3
"""Minimal dependency-free Cargo package metadata reader for QA scripts.

The release QA only needs string keys from the root [package] table. Keeping
this parser intentionally narrow avoids requiring Python 3.11's tomllib or an
external tomli installation on Windows.
"""
from pathlib import Path
import re

_SECTION = re.compile(r"^\s*\[([^\]]+)\]\s*(?:#.*)?$")
_STRING = re.compile(r'^\s*([A-Za-z0-9_-]+)\s*=\s*"((?:\\.|[^"\\])*)"\s*(?:#.*)?$')


def read_package(path):
    """Return simple string fields from a Cargo.toml [package] table."""
    path = Path(path)
    package = {}
    in_package = False
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        section = _SECTION.match(raw_line)
        if section:
            in_package = section.group(1).strip() == "package"
            continue
        if not in_package:
            continue
        match = _STRING.match(raw_line)
        if match:
            key, value = match.groups()
            package[key] = bytes(value, "utf-8").decode("unicode_escape")
    return package
