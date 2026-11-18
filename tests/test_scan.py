import textwrap

from holdout import scan


def _sites(make_repo, files):
    root = make_repo(files)
    return scan.scan_repo(root)


def test_sink_discovery_each_family(make_repo):
    res = _sites(
        make_repo,
        {
            "m.py": textwrap.dedent(
                """
                import json, subprocess, os
                def f(data, fh, uid):
                    json.loads(data)
                    fh.read()
                    subprocess.run(["ls"], env=os.environ)

                @app.route("/admin/x")
                def admin_x():
                    delete_user(uid)
                """
            )
        },
    )
    fams = {s.family for s in res.sites}
    assert "input-validation" in fams and "size-cap" in fams and "auth-check" in fams


def test_bounded_read_not_a_site(make_repo):
    res = _sites(
        make_repo,
        {"m.py": "def f(fh):\n    fh.read(4096)\n"},
    )
    assert not res.sites


def test_early_exit_guard_counts(make_repo):
    res = _sites(
        make_repo,
        {
            "m.py": textwrap.dedent(
                """
                import json
                def f(data):
                    if len(data) > 10:
                        return
                    f2 = open(data)
                    return f2.read()
                """
            )
        },
    )
    sc = [s for s in res.sites if s.family == "size-cap"]
    assert sc and sc[0].guard_present


def test_non_dominating_sibling_check_does_not_count(make_repo):
    res = _sites(
        make_repo,
        {
            "m.py": textwrap.dedent(
                """
                def f(fh, c, x):
                    if c:
                        if len(fh) > 0:
                            x = fh
                    fh.read()
                """
            )
        },
    )
    sc = [s for s in res.sites if s.family == "size-cap"]
    assert sc and not sc[0].guard_present


def test_membership_guard_and_identity(make_repo):
    res = _sites(
        make_repo,
        {
            "m.py": textwrap.dedent(
                """
                import json
                ALLOWED = {"a", "b"}
                def f(data):
                    if data not in ALLOWED:
                        return
                    json.loads(data)
                """
            )
        },
    )
    s = [x for x in res.sites if x.operation == "json.loads"][0]
    assert s.guard_present and s.guard_identity == "membership:ALLOWED"


def test_comprehension_filter_guards_produced_name(make_repo):
    res = _sites(
        make_repo,
        {
            "m.py": textwrap.dedent(
                """
                import subprocess
                BLOCK = {"LD_PRELOAD"}
                def f():
                    env = {k: v for k, v in os_environ_items() if k not in BLOCK}
                    subprocess.run(["x"], env=env)
                """
            )
        },
    )
    s = [x for x in res.sites if x.group.startswith("subprocess.run#env")][0]
    assert s.guard_present and s.guard_identity == "membership:BLOCK"


def test_named_sanitizer_assignment(make_repo):
    res = _sites(
        make_repo,
        {
            "m.py": textwrap.dedent(
                """
                import subprocess, os
                def f():
                    env = sanitize_env(os.environ)
                    subprocess.run(["x"], env=env)
                """
            )
        },
    )
    s = [x for x in res.sites if x.group.startswith("subprocess.run#env")][0]
    assert s.guard_present and s.guard_identity == "check:sanitize_env"


def test_unguarded_env_site(make_repo):
    res = _sites(
        make_repo,
        {
            "m.py": textwrap.dedent(
                """
                import subprocess, os
                def f():
                    env = os.environ.copy()
                    subprocess.run(["x"], env=env)
                """
            )
        },
    )
    s = [x for x in res.sites if x.group.startswith("subprocess.run#env")][0]
    assert not s.guard_present


def test_nested_qualname_attribution(make_repo):
    res = _sites(
        make_repo,
        {
            "m.py": textwrap.dedent(
                """
                import json
                class A:
                    def m(self, data):
                        def inner():
                            return json.loads(data)
                        return inner()
                """
            )
        },
    )
    s = res.sites[0]
    assert s.function == "A.m.inner"  # PEP-3155 qualname of the nested frame


def test_module_scope_is_frame(make_repo):
    res = _sites(
        make_repo,
        {"m.py": "import json\nif 'x' in {'x'}:\n    pass\njson.loads(d)\n"},
    )
    s = res.sites[0]
    assert s.function == "<module>"


def test_divergent_operand_keeps_distinct_identity(make_repo):
    res = _sites(
        make_repo,
        {
            "m.py": textwrap.dedent(
                """
                import json
                A = {"x"}
                B = {"y"}
                def f(d):
                    if d in A:
                        json.loads(d)
                def g(d):
                    if d in B:
                        json.loads(d)
                """
            )
        },
    )
    ids = {s.guard_identity for s in res.sites}
    assert ids == {"membership:A", "membership:B"}


def test_url_consume_sink(make_repo):
    res = _sites(
        make_repo,
        {
            "m.py": textwrap.dedent(
                """
                def f(hdr):
                    JiraConfig(url=hdr)
                    Other(base_url="https://const.example")
                    Third(name=hdr)
                """
            )
        },
    )
    urls = [s for s in res.sites if s.group.startswith("JiraConfig#url") or s.group.startswith("urllib.request.urlopen#")]
    assert len(urls) == 1 and urls[0].operation.endswith("JiraConfig")


def test_http_verb_positional(make_repo):
    res = _sites(
        make_repo,
        {
            "m.py": "import urllib.request\ndef f(u):\n    urllib.request.urlopen(u)\n"
        },
    )
    urls = [s for s in res.sites if s.group.startswith("JiraConfig#url") or s.group.startswith("urllib.request.urlopen#")]
    assert urls and "urllib.request.urlopen" in urls[0].operation
