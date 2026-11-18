"""Vendored / generated / test-tree path exclusion markers.

Sites under these markers contribute to neither consensus nor candidates.
Matching is segment-exact on path components, never substring.
"""

from __future__ import annotations

import fnmatch
import os

# Directory names that exclude a whole subtree, by marker class.
VENDORED_DIRS = (
    "vendor",
    "third_party",
    "node_modules",
    ".tox",
    "venv",
    ".venv",
    "site-packages",
)
TEST_DIRS = ("tests", "test", "_tests", "fixtures")
# build/IDE/scm noise + analysis-tool harness dirs: never consensus-relevant.
INTERNAL_DIRS = (
    ".git", "__pycache__", "build", "dist", ".eggs",
    ".autocatalytic", ".clawpatch",
)

EXCLUDED_DIRS = VENDORED_DIRS + TEST_DIRS + INTERNAL_DIRS

# Basename patterns that exclude a single file.
GENERATED_FILES = ("*_pb2.py", "*.generated.py")
TEST_FILES = ("test_*.py", "*_test.py", "conftest.py")

EXCLUDED_FILES = GENERATED_FILES + TEST_FILES


def _file_class(base: str) -> str:
    if any(fnmatch.fnmatchcase(base, p) for p in GENERATED_FILES):
        return "vendored"
    if any(fnmatch.fnmatchcase(base, p) for p in TEST_FILES):
        return "test"
    return ""


def marker_class(relpath: str) -> str:
    """Marker class ('vendored'|'test'|'internal') or '' when not excluded."""
    parts = relpath.split(os.sep)
    for d in parts[:-1]:
        if d in VENDORED_DIRS:
            return "vendored"
        if d in TEST_DIRS:
            return "test"
        if d in INTERNAL_DIRS:
            return "internal"
    return _file_class(parts[-1])


def is_excluded(relpath: str) -> bool:
    """True when a repo-relative path sits under an exclusion marker."""
    return bool(marker_class(relpath))


def is_excluded_dir(dirname: str) -> str:
    """Marker class for a directory component itself ('' when kept)."""
    if dirname in VENDORED_DIRS:
        return "vendored"
    if dirname in TEST_DIRS:
        return "test"
    if dirname in INTERNAL_DIRS:
        return "internal"
    return ""
