"""Exposure resolution: --exposure-file JSON map, else scope-boundary.md.

The scope-boundary parser accepts a provisional shape pinned by
tests/fixtures/scope-boundary.md: lines of the form

    - path/to/file.py:function_name TAINT: yes
    - path/to/file.py:function_name TAINT: yes entry=POST /api/x

A malformed or oversized scope-boundary file is ignored with a stderr
warning, never a crash or partial apply: it is untrusted input when the
scanned target is third-party code.
"""

from __future__ import annotations

import json
import os
import re
import sys

BUCKETS = ("untrusted", "internal", "unknown")
_MAX_BYTES = 1024 * 1024
_TAINT_RE = re.compile(r"^\s*[-*]?\s*(\S+):(\S+)\s+TAINT:\s*yes\b(.*)$", re.IGNORECASE)
_ENTRY_RE = re.compile(r"\bentry=([^\s]+)", re.IGNORECASE)


class ExposureError(Exception):
    pass


def _load_map(path: str) -> dict:
    try:
        if os.path.getsize(path) > _MAX_BYTES:
            raise ExposureError(f"exposure file {path} oversized")
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError) as e:
        raise ExposureError(f"cannot read exposure file {path}: {e}")
    if not isinstance(data, dict):
        raise ExposureError(f"exposure file {path} is not a JSON object")
    out = {}
    for k, v in data.items():
        if v not in BUCKETS:
            raise ExposureError(f"exposure file {path}: bad bucket {v!r} for {k!r}")
        out[k] = v
    return out


def _parse_scope_boundary(path: str) -> dict:
    """Return {'path:func': bucket} plus entry ids under 'entry:<key>'."""
    try:
        if os.path.getsize(path) > _MAX_BYTES:
            raise ValueError("scope-boundary.md oversized")
        with open(path, "r", encoding="utf-8") as fh:
            text = fh.read()
    except (OSError, ValueError) as e:
        print(f"holdout: ignoring unreadable scope-boundary.md: {e}", file=sys.stderr)
        return {}
    out = {}
    for line in text.splitlines():
        m = _TAINT_RE.match(line)
        if not m:
            continue
        key = f"{m.group(1)}:{m.group(2)}"
        out[key] = "untrusted"
        e = _ENTRY_RE.search(m.group(3) or "")
        if e:
            out[f"entry:{key}"] = e.group(1)
    return out


def load_exposure(repo_root: str, exposure_file: str = None) -> dict:
    """Resolve the exposure map. Key 'path:function' -> bucket; entry ids
    ride under 'entry:path:function'."""
    if exposure_file:
        return _load_map(exposure_file)
    sb = os.path.join(repo_root, ".clawpatch", "scope-boundary.md")
    if os.path.isfile(sb):
        # symlinked scope-boundary files resolving outside the root are
        # untrusted-input escapes: read through a realpath confinement check
        # identical to the scanner's.
        real = os.path.realpath(sb)
        if not real.startswith(os.path.realpath(repo_root) + os.sep):
            print("holdout: ignoring scope-boundary.md resolving outside root",
                  file=sys.stderr)
            return {}
        return _parse_scope_boundary(sb)
    return {}


def apply_exposure(sites: list, emap: dict) -> None:
    for s in sites:
        key = f"{s.path}:{s.function}"
        s.exposure = emap.get(key, "unknown")
        s.entry = emap.get(f"entry:{key}")
