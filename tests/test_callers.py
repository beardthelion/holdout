import textwrap

from holdout import scan
from holdout.callers import apply_caller_walk, build_def_index


def _scan(make_repo, files):
    root = make_repo(files)
    return scan.scan_repo(root)


def _run(res, depth=2):
    apply_caller_walk(res.sites, res.modules, depth)
    return res.sites


def test_caller_guard_depth1(make_repo):
    res = _scan(
        make_repo,
        {
            "m.py": textwrap.dedent(
                """
                import json
                def sink(d):
                    return json.loads(d)
                def caller(x):
                    if x not in ALLOWED:
                        return
                    sink(x)
                """
            )
        },
    )
    s = res.sites[0]
    _run(res)
    assert s.guard_present


def test_caller_guard_depth2_not_depth1_when_flag0(make_repo):
    res = _scan(
        make_repo,
        {
            "m.py": textwrap.dedent(
                """
                import json
                def sink(d):
                    return json.loads(d)
                def mid(x):
                    sink(x)
                def top(x):
                    if x not in ALLOWED:
                        return
                    mid(x)
                """
            )
        },
    )
    s = res.sites[0]
    _run(res, depth=2)
    assert s.guard_present
    s.guard_present = False
    s.guard_identity = None
    _run(res, depth=1)
    assert not s.guard_present


def test_depth0_explicit(make_repo):
    res = _scan(
        make_repo,
        {
            "m.py": "import json\ndef sink(d):\n    return json.loads(d)\n"
            "def c(x):\n    if x in A: sink(x)\n"
        },
    )
    s = res.sites[0]
    _run(res, depth=0)
    assert not s.guard_present


def test_guard_on_unrelated_caller_local_does_not_clear(make_repo):
    res = _scan(
        make_repo,
        {
            "m.py": textwrap.dedent(
                """
                import json
                def sink(d):
                    return json.loads(d)
                def caller(x, y):
                    if y not in ALLOWED:
                        return
                    sink(x)
                """
            )
        },
    )
    s = res.sites[0]
    _run(res)
    assert not s.guard_present


def test_any_caller_rule(make_repo):
    res = _scan(
        make_repo,
        {
            "m.py": textwrap.dedent(
                """
                import json
                def sink(d):
                    return json.loads(d)
                def a(x):
                    sink(x)
                def b(x):
                    sink(x)
                def c(x):
                    if x not in ALLOWED:
                        return
                    sink(x)
                """
            )
        },
    )
    s = res.sites[0]
    _run(res)
    assert s.guard_present


def test_sanitizer_resolved_body(make_repo):
    res = _scan(
        make_repo,
        {
            "m.py": textwrap.dedent(
                """
                import subprocess, os
                BLOCK = {"X"}
                def scrub_env(e):
                    return {k: v for k, v in e.items() if k not in BLOCK}
                def f():
                    env = scrub_env(os.environ)
                    subprocess.run(["x"], env=env)
                """
            )
        },
    )
    s = [x for x in res.sites if x.group.startswith("subprocess.run#env")][0]
    _run(res)
    assert s.guard_present and s.guard_identity == "membership:BLOCK"


def test_same_name_different_modules(make_repo):
    res = _scan(
        make_repo,
        {
            "a.py": "import json\ndef load(d):\n    return json.loads(d)\n",
            "b.py": textwrap.dedent(
                """
                import json
                def load(d):
                    return json.loads(d)
                def caller(x):
                    if x not in OK:
                        return
                    a_load_placeholder = None
                """
            ),
        },
    )
    # both load() sites unguarded; no cross-module merge invents a guard
    _run(res)
    assert all(not s.guard_present for s in res.sites)


def test_cycle_terminates(make_repo):
    res = _scan(
        make_repo,
        {
            "m.py": "import json\ndef a(x):\n    return json.loads(x)\ndef b(x):\n    a(x)\ndef a2(x):\n    b(x)\n"
        },
    )
    _run(res)
    assert True  # no hang / error


def test_decorator_only_unreachable_evaluates_sink_only(make_repo):
    res = _scan(
        make_repo,
        {
            "m.py": "import json\nREGISTRY = []\n"
            "def reg(f):\n    REGISTRY.append(f)\n    return f\n"
            "@reg\ndef sink(d):\n    return json.loads(d)\n"
        },
    )
    _run(res)
    assert not res.sites[0].guard_present


def test_def_index_qualified_names(make_repo):
    res = _scan(
        make_repo,
        {"pkg/m.py": "def outer():\n    def inner():\n        pass\n"},
    )
    idx = build_def_index(res.modules)
    assert ("pkg.m", "outer") in idx
