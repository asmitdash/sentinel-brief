"""Lightweight version-range membership check.

OSV/GHSA ranges are ecosystem-relative. We don't ship a full PEP 440 / semver
implementation — we use a tuple-based loose comparator that handles the common
cases (`X.Y.Z` digits and trailing tags). Edge cases (rc/dev/build metadata)
fall back to string comparison, which is conservative enough for a Week-2 MVP.
"""

from __future__ import annotations

import re

_VERSION_RE = re.compile(r"^(\d+(?:\.\d+)*)(?:[-+.](.*))?$")


def _key(v: str | None) -> tuple:
    if not v:
        return ((),)
    m = _VERSION_RE.match(v.strip())
    if not m:
        return ((0,), v)
    nums = tuple(int(p) for p in m.group(1).split("."))
    rest = m.group(2) or ""
    return (nums, rest)


def cmp(a: str, b: str) -> int:
    ka, kb = _key(a), _key(b)
    if ka < kb:
        return -1
    if ka > kb:
        return 1
    return 0


def in_range(
    version: str,
    introduced: str | None,
    fixed: str | None,
    last_affected: str | None,
) -> bool:
    """True if `version` is in [introduced, fixed) or [introduced, last_affected]."""
    if introduced and introduced != "0" and cmp(version, introduced) < 0:
        return False
    if fixed:
        if cmp(version, fixed) >= 0:
            return False
    elif last_affected:
        if cmp(version, last_affected) > 0:
            return False
    return True
