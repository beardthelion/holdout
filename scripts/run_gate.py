#!/usr/bin/env python3
"""Known-answer gate for Holdout.

Pass-gated legs run on vendored fixtures under tests/fixtures/ and are
deterministic on any box: the expected non-conforming site must be emitted
as a candidate and rank in the top 10 of the run (SPEC's bar, not
"appears anywhere"). Real-repo legs run only when their root env var is
set (HOLDOUT_MCP_VULN_ROOT); they are recorded informationally, never skipped
silently and never pass-gated on a machine that lacks the checkout.
"""

import json
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from holdout import cli
from holdout.cli import HoldoutError

FIX = os.path.join(os.path.dirname(__file__), "..", "tests", "fixtures")
NOTE = os.path.join(os.path.dirname(__file__), "..", "docs", "gate-results.md")

# deterministic, pass-gated legs on vendored fixtures
CASES = [
    {
        "name": "env-scrub fixture",
        "root": os.path.join(FIX, "env-scrub-house"),
        "expect_path": "runner_bad.py",
        "expect_function": "run_experiment",
        "expect_op": "subprocess.run",
        "family": "input-validation",
    },
    {
        "name": "auth-check fixture",
        "root": os.path.join(FIX, "auth-house"),
        "expect_path": "server.py",
        "expect_function": "start_export_job",
        "expect_op": "@app.post",
        "family": "auth-check",
    },
]

# real-repo legs: run when the env var points at a checkout; informational
REAL_CASES = [
    {
        "name": "mcp-atlassian SSRF",
        "env": "HOLDOUT_MCP_VULN_ROOT",
        "expect_path": "src/mcp_atlassian/servers/dependencies.py",
        "expect_function": None,
        "expect_op": None,
        "family": "input-validation",
    },
]


def _rows(root):
    with tempfile.TemporaryDirectory() as td:
        out = os.path.join(td, "o.jsonl")
        rc = cli.run(root, out)
        if rc != 0:
            raise HoldoutError(f"holdout exited {rc}")
        with open(out) as fh:
            return [json.loads(l) for l in fh]


def _eval(rows, case):
    cands = [r for r in rows if r["type"] == "candidate"]
    total = len(cands)
    idx = None
    for i, r in enumerate(cands):
        s = r["sink"]
        if (
            s["path"] == case["expect_path"]
            and (case["expect_function"] is None
                 or s["function"] == case["expect_function"])
            and (case["expect_op"] is None or s["operation"] == case["expect_op"])
        ):
            idx = i
            break
    fam_c = [r for r in cands if r["family"] == case["family"]]
    in_family = next(
        (i for i, r in enumerate(fam_c) if cands.index(r) == idx), None
    ) if idx is not None else None
    rec = {
        "case": case["name"],
        "expected": f"{case['expect_path']}:{case['expect_function']}",
        "emitted_total": total,
        "observed_ordinal": idx,
        "observed_family_ordinal": in_family,
        "verdict": None,
        "note": "",
    }
    if case.get("informational"):
        rec["verdict"] = "informational"
        rec["note"] = (
            f"emitted ordinal={idx} of {total} candidates"
            if idx is not None else "expected site not emitted"
        )
        return rec
    # restored top-10 bar
    if idx is None:
        rec["verdict"] = "fail"
        rec["note"] = "expected site not emitted"
    else:
        bar = "top-10" if total >= 10 else "top-of-family"
        ok = idx < 10 if total >= 10 else in_family == 0
        rec["verdict"] = "pass" if ok else "fail"
        rec["note"] = f"bar={bar} ordinal={idx} fam_ordinal={in_family}"
    return rec


def _negative_control():
    """env-scrub fixture minus the known-bad file must emit zero."""
    src = os.path.join(FIX, "env-scrub-house")
    with tempfile.TemporaryDirectory() as td:
        dst = os.path.join(td, "tree")
        shutil.copytree(src, dst)
        os.remove(os.path.join(dst, "runner_bad.py"))
        rows = _rows(dst)
    cands = [r for r in rows if r["type"] == "candidate"]
    return {
        "case": "env-scrub conforming-only negative control",
        "verdict": "pass" if not cands else "fail",
        "note": f"candidates emitted: {len(cands)}",
    }


def _run_case(case, informational=False):
    case = dict(case, informational=informational)
    root = case.get("root") or os.environ.get(case["env"], "")
    if not root or not os.path.isdir(root):
        return {"case": case["name"], "root": root,
                "verdict": "skip", "note": f"set {case.get('env')} to run"}
    try:
        return _eval(_rows(root), case)
    except Exception as e:
        return {"case": case["name"], "root": root,
                "verdict": "fail", "note": f"run failed: {e}"}


def main():
    recs = [_run_case(c) for c in CASES]
    recs.append(_negative_control())
    for c in REAL_CASES:
        if os.environ.get(c["env"]):
            recs.append(_run_case(c, informational=True))
        else:
            recs.append({"case": c["name"], "verdict": "skip",
                         "note": f"{c['env']} not set"})
    os.makedirs(os.path.dirname(NOTE), exist_ok=True)
    with open(NOTE, "w") as fh:
        fh.write("# Gate results\n\n")
        for r in recs:
            fh.write(f"## {r['case']}\n")
            for k in ("root", "expected", "emitted_total",
                      "observed_ordinal", "observed_family_ordinal", "note"):
                if k in r and r[k] is not None:
                    fh.write(f"- {k}: {r[k]}\n")
            fh.write(f"- verdict: {r['verdict']}\n\n")
    print(f"wrote {NOTE}")
    for r in recs:
        print(f"{r['case']}: {r['verdict']} {r.get('note','')}")
    gated = [r for r in recs if r["verdict"] not in ("informational", "skip")]
    return 0 if all(r["verdict"] == "pass" for r in gated) else 1


if __name__ == "__main__":
    raise SystemExit(main())
