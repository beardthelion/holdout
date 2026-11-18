import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))


@pytest.fixture
def make_repo(tmp_path):
    """Write a synthetic repo tree from {relpath: source} and return root."""

    def _make(files: dict) -> str:
        for rel, content in files.items():
            p = tmp_path / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            if content is not None:
                p.write_text(content)
        return str(tmp_path)

    return _make


@pytest.fixture
def read_jsonl():
    def _read(path):
        with open(path) as fh:
            return [json.loads(line) for line in fh if line.strip()]

    return _read
