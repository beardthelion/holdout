import json
import os

from holdout import cli


def test_happy_path(make_repo, tmp_path, capsys):
    root = make_repo({"m.py": "import json\ndef f(d):\n    return json.loads(d)\n"})
    out = tmp_path / "o.jsonl"
    rc = cli.main([root, "--out", str(out)])
    assert rc == 0
    cap = capsys.readouterr().out.strip()
    assert cap.startswith("families=3")
    assert out.exists()
    hdrs = [json.loads(l) for l in out.read_text().splitlines() if '"family"' in l]
    assert len(hdrs) == 3


def test_unknown_family_rejected(make_repo, tmp_path, capsys):
    root = make_repo({"m.py": "x=1\n"})
    out = tmp_path / "o.jsonl"
    rc = cli.main([root, "--out", str(out), "--families", "not-a-family"])
    assert rc != 0
    assert "holdout: stopped:" in capsys.readouterr().err
    assert not out.exists()


def test_flag_ranges(make_repo, tmp_path):
    root = make_repo({"m.py": "x=1\n"})
    out = tmp_path / "o.jsonl"
    assert cli.main([root, "--out", str(out), "--threshold", "1.5"]) != 0
    assert cli.main([root, "--out", str(out), "--caller-depth", "-1"]) != 0
    assert cli.main([root, "--out", str(out), "--caller-depth", "0"]) == 0


def test_unreadable_root(tmp_path):
    assert cli.main(["/no/such/dir", "--out", str(tmp_path / "o.jsonl")]) != 0


def test_zero_parsed_files(tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    assert cli.main([str(empty), "--out", str(tmp_path / "o.jsonl")]) != 0


def test_families_intersection(make_repo, tmp_path):
    root = make_repo({"m.py": "import json\ndef f(d):\n    json.loads(d)\n"})
    out = tmp_path / "o.jsonl"
    assert cli.main([root, "--out", str(out), "--families", "input-validation"]) == 0
    rows = [json.loads(l) for l in out.read_text().splitlines()]
    fams = [r for r in rows if r["type"] == "family"]
    assert len(fams) == 1 and fams[0]["family"] == "input-validation"


def test_summary_counts_match_rows(make_repo, tmp_path, capsys):
    root = make_repo({"m.py": "x=1\n"})
    out = tmp_path / "o.jsonl"
    cli.main([root, "--out", str(out)])
    cap = capsys.readouterr().out.strip()
    rows = [json.loads(l) for l in out.read_text().splitlines()]
    cands = sum(1 for r in rows if r["type"] == "candidate")
    silents = sum(1 for r in rows if r["type"] == "family" and r["status"].endswith("silent"))
    assert f"candidates={cands}" in cap
    assert f"silent={silents}" in cap


def test_also_md_written(make_repo, tmp_path):
    root = make_repo({"m.py": "x=1\n"})
    out = tmp_path / "o.jsonl"
    assert cli.main([root, "--out", str(out), "--also-md"]) == 0
    assert (tmp_path / "o.md").exists()


def test_end_to_end_candidate(make_repo, read_jsonl, tmp_path):
    guarded = "\n".join(
        f"def g{i}(d):\n    if d not in A:\n        return\n    open(d)\n" for i in range(6)
    )
    root = make_repo(
        {
            "m.py": "A = {'x'}\n" + guarded + "def f(d):\n    open(d)\n"
        }
    )
    out = tmp_path / "o.jsonl"
    assert cli.main([root, "--out", str(out)]) == 0
    rows = read_jsonl(out)
    cands = [r for r in rows if r["type"] == "candidate"]
    assert len(cands) == 1
    assert cands[0]["sink"]["function"] == "f"
    assert cands[0]["missing_guard"] == "membership:A"
