import json
import os

import pytest

from holdout import exposure
from holdout.scan import Site

FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "scope-boundary.md")


def _site(path="a.py", fn="f"):
    return Site("input-validation", "g", path, fn, 1, "open", frozenset())


def test_map_file(tmp_path):
    f = tmp_path / "exp.json"
    f.write_text(json.dumps({"a.py:f": "untrusted", "b.py:g": "internal"}))
    emap = exposure.load_exposure("root", str(f))
    sites = [_site("a.py", "f"), _site("b.py", "g"), _site("c.py", "h")]
    exposure.apply_exposure(sites, emap)
    assert [s.exposure for s in sites] == ["untrusted", "internal", "unknown"]


def test_malformed_map_raises(tmp_path):
    f = tmp_path / "exp.json"
    f.write_text("{not json")
    with pytest.raises(exposure.ExposureError):
        exposure.load_exposure("root", str(f))


def test_bad_bucket_raises(tmp_path):
    f = tmp_path / "exp.json"
    f.write_text(json.dumps({"a.py:f": "elevated"}))
    with pytest.raises(exposure.ExposureError):
        exposure.load_exposure("root", str(f))


def test_no_inputs_all_unknown(tmp_path):
    emap = exposure.load_exposure(str(tmp_path))
    s = _site()
    exposure.apply_exposure([s], emap)
    assert s.exposure == "unknown" and s.entry is None


def test_scope_boundary_fixture(tmp_path):
    cp = tmp_path / ".clawpatch"
    cp.mkdir()
    (cp / "scope-boundary.md").write_text(open(FIXTURE).read())
    emap = exposure.load_exposure(str(tmp_path))
    assert emap["app/web.py:handle"] == "untrusted"
    assert emap["entry:app/api.py:rpc"] == "POST"
    s = _site("app/web.py", "handle")
    exposure.apply_exposure([s], emap)
    assert s.exposure == "untrusted"


def test_flag_overrides_scope_boundary(tmp_path):
    cp = tmp_path / ".clawpatch"
    cp.mkdir()
    (cp / "scope-boundary.md").write_text("- a.py:f TAINT: yes\n")
    f = tmp_path / "exp.json"
    f.write_text(json.dumps({"a.py:f": "internal"}))
    emap = exposure.load_exposure(str(tmp_path), str(f))
    assert emap["a.py:f"] == "internal"
