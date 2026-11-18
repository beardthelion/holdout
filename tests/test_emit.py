import json
import os
import re

import pytest

from holdout import consensus, emit
from holdout.scan import ParseErrorRec, Site


def _site(fam, group, path, fn, line, guarded=False, gid=None, exposure="unknown", op="json.loads"):
    s = Site(fam, group, path, fn, line, op, frozenset())
    s.guard_present = guarded
    s.guard_identity = gid
    s.exposure = exposure
    return s


from holdout import families as _fams

CANON = _fams.FAMILIES


def _results(sites, considered=CANON):
    return consensus.compute(sites, considered, 0.8, 5)


def test_header_schema_and_candidates(make_repo, read_jsonl, tmp_path):
    sites = [_site("input-validation", "g1", "a.py", "f", i, True, "membership:A") for i in range(6)]
    sites += [_site("input-validation", "g1", "a.py", "f", 99)]
    res = _results(sites)
    ranked = consensus.rank_candidates(res, CANON)
    rows = emit.build_rows(res, CANON, 0.8, ranked, [],
                           {"files": 2, "dirs": 1})
    out = tmp_path / "o.jsonl"
    emit.write_outputs(rows, str(out))
    rows2 = read_jsonl(out)
    hdrs = [r for r in rows2 if r["type"] == "family"]
    assert len(hdrs) == 3
    assert hdrs[0]["family"] == "size-cap"  # spec table order
    assert hdrs[1]["reason"] is None and hdrs[1]["status"] == "active"
    assert hdrs[2]["status"] == "no house rule, silent" and hdrs[2]["reason"] == "too-few-sites"
    cand = [r for r in rows2 if r["type"] == "candidate"][0]
    assert re.fullmatch(r"holdout-input-validation-[0-9a-f]{10}", cand["id"])
    assert cand["missing_guard"] == "membership:A"
    assert len(cand["siblings"]) <= 3
    assert cand["entry"] is None
    assert "vulnerab" not in out.read_text().lower()


def test_determinism(tmp_path):
    sites = [_site("input-validation", "g", "a.py", "f", i, True, "m:A") for i in range(6)]
    sites += [_site("input-validation", "g", "b.py", "g", 1)]
    res = _results(sites)
    ranked = consensus.rank_candidates(res, CANON)
    r1 = emit.build_rows(res, CANON, 0.8, ranked,
                         [ParseErrorRec("x.py", "SyntaxError")], {})
    a, b = tmp_path / "a.jsonl", tmp_path / "b.jsonl"
    emit.write_outputs(r1, str(a))
    emit.write_outputs(r1, str(b))
    assert a.read_bytes() == b.read_bytes()


def test_atomic_write_failure_leaves_no_partial(tmp_path):
    rows = [{"type": "family"}]
    out2 = tmp_path / "nowrite" / "o.jsonl"
    out2.parent.mkdir()
    os.chmod(out2.parent, 0o500)
    try:
        with pytest.raises(OSError):
            emit.write_outputs(rows, str(out2))
        assert not out2.exists()
        leftovers = [f for f in os.listdir(out2.parent) if f.startswith(".holdout-")]
        assert not leftovers
    finally:
        os.chmod(out2.parent, 0o700)


def test_markdown_sections():
    sites = [_site("input-validation", "g", "a.py", "f", i, True, "m:A") for i in range(6)]
    sites += [_site("input-validation", "g", "a.py", "f", 50)]
    res = _results(sites)
    ranked = consensus.rank_candidates(res, CANON)
    md = emit.render_markdown(res, ("input-validation", "size-cap", "auth-check"), ranked)
    assert "## input-validation" in md and "1. `a.py:f:50`" in md
    assert "## Silent families" in md and "size-cap" in md
    assert "vulnerab" not in md.lower() and "severity" not in md.lower()
