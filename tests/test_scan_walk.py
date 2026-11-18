import os

from holdout import scan


def test_walk_sorted_and_counts(make_repo):
    root = make_repo(
        {"b.py": "x=1\n", "a.py": "x=1\n", "pkg/c.py": "x=1\n"}
    )
    res = scan.scan_repo(root)
    assert res.files_parsed == 3
    assert list(res.modules) == ["a", "b", "pkg.c"]


def test_exclusion_markers(make_repo):
    root = make_repo(
        {
            "main.py": "import json\njson.loads(x)\n",
            "vendor/v.py": "json.loads(y)\n",
            "tests/t.py": "json.loads(y)\n",
            "x_pb2.py": "json.loads(y)\n",
            "y.generated.py": "json.loads(y)\n",
            "node_modules/n.py": "json.loads(y)\n",
        }
    )
    res = scan.scan_repo(root)
    assert res.files_parsed == 1
    # vendored/generated basenames count as files; marker dirs count as dirs
    # (files under pruned dirs are never enumerated)
    assert res.excluded_files == 2
    assert res.excluded_dirs == 3
    assert res.by_marker["vendored"] >= 3
    assert all(s.path == "main.py" for s in res.sites)


def test_parse_errors_do_not_abort(make_repo):
    root = make_repo(
        {
            "ok.py": "x = 1\n",
            "bad.py": "def broken(:\n",
            "latin.py": None,  # written below as non-utf8
        }
    )
    with open(os.path.join(root, "latin.py"), "wb") as fh:
        fh.write(b"# -*- coding: latin-1 -*-\nx = '\xe9'\n")
    res = scan.scan_repo(root)
    assert res.files_parsed == 1
    kinds = {e.path for e in res.parse_errors}
    assert "bad.py" in kinds and "latin.py" in kinds


def test_recursion_error_skipped(make_repo):
    root = make_repo({"deep.py": "x = " + "(" * 5000 + "1" + ")" * 5000 + "\n", "ok.py": "y=1\n"})
    res = scan.scan_repo(root)
    assert res.files_parsed == 1
    assert any(e.path == "deep.py" for e in res.parse_errors)


def test_symlink_outside_root_excluded(tmp_path):
    outside = tmp_path / "outside.py"
    outside.write_text("import json\njson.loads(x)\n")
    root = tmp_path / "repo"
    root.mkdir()
    (root / "in.py").write_text("x=1\n")
    os.symlink(str(outside), str(root / "link.py"))
    res = scan.scan_repo(str(root))
    assert res.files_parsed == 1
    assert all(s.path == "in.py" for s in res.sites)


def test_root_inside_excluded_tree_still_scans(tmp_path):
    vendored = tmp_path / "vendor" / "pkg"
    vendored.mkdir(parents=True)
    (vendored / "m.py").write_text("import json\ndef f(x):\n    return json.loads(x)\n")
    res = scan.scan_repo(str(vendored))
    assert res.files_parsed == 1
    assert res.sites


def test_walk_deterministic(make_repo):
    files = {f"d{i}/m{i}.py": "x=1\n" for i in range(5)}
    files["z.py"] = "x=1\n"
    files["a.py"] = "x=1\n"
    root = make_repo(files)
    a = [s for s in scan.scan_repo(root).modules]
    b = [s for s in scan.scan_repo(root).modules]
    assert a == b
