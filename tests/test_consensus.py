from holdout import consensus
from holdout.scan import Site


def _site(fam="input-validation", group="json.loads", path="a.py", fn="f", line=1,
          guarded=False, gid=None, exposure="unknown"):
    s = Site(fam, group, path, fn, line, "json.loads", frozenset())
    s.guard_present = guarded
    s.guard_identity = gid
    s.exposure = exposure
    return s


def _run(sites, threshold=0.8, floor=5):
    return consensus.compute(sites, ("input-validation",), threshold, floor)


def test_active_and_silent_threshold():
    # 10 conforming of 12 -> .833 active; 9 of 12 -> .75 silent
    sites = [_site(line=i, guarded=True, gid="membership:A") for i in range(10)]
    sites += [_site(line=20 + i) for i in range(2)]
    r = _run(sites)["input-validation"]
    assert r.status == "active" and abs(r.consensus - 10 / 12) < 1e-9
    r2 = _run(sites[:11])["input-validation"]
    # 9 of 11 -> .818 still active; make below-threshold case
    sites_b = [_site(line=i, guarded=True, gid="membership:A") for i in range(8)]
    sites_b += [_site(line=30 + i) for i in range(4)]
    rb = _run(sites_b)["input-validation"]
    assert rb.status == "no house rule, silent" and rb.reason == "below-threshold"


def test_too_few_sites_floor():
    sites = [_site(line=i, guarded=True, gid="membership:A") for i in range(4)]
    r = _run(sites)["input-validation"]
    assert r.status == "no house rule, silent" and r.reason == "too-few-sites"


def test_zero_sites_null_consensus():
    r = _run([])["input-validation"]
    assert r.consensus is None and r.reason == "too-few-sites" and r.status.endswith("silent")


def test_dominant_identity_and_divergent_candidate():
    sites = [_site(line=i, guarded=True, gid="membership:A") for i in range(6)]
    sites += [_site(line=9, guarded=True, gid="type:B")]
    r = _run(sites)["input-validation"]
    assert r.status == "active"
    assert len(r.candidates) == 1
    assert r.candidates[0].missing_guard == "membership:A"


def test_6040_split_goes_silent():
    sites = [_site(line=i, guarded=True, gid="membership:A") for i in range(6)]
    sites += [_site(line=10 + i, guarded=True, gid="type:B") for i in range(4)]
    r = _run(sites)["input-validation"]
    assert r.status == "no house rule, silent" and r.reason == "below-threshold"
    assert r.consensus == 0.6


def test_zero_guarded_group_emits_nothing():
    # group json.loads all unguarded; env-spawn group fully guarded w/ dominant
    sites = [_site(line=i) for i in range(5)]
    sites += [
        _site(group="subprocess.run#env", line=20 + i, guarded=True, gid="membership:B")
        for i in range(6)
    ]
    r = _run(sites)["input-validation"]
    assert r.status == "active"
    assert all(c.site.group.startswith("subprocess.run#env") for c in r.candidates) or not r.candidates


def test_rank_arithmetic_and_ties():
    a = _site(path="b.py", line=1, exposure="unknown")
    b = _site(path="a.py", line=2, exposure="untrusted")
    sites = [_site(line=i, guarded=True, gid="membership:A") for i in range(8)]
    sites += [a, b]
    res = _run(sites)
    ranked = consensus.rank_candidates(res, ("input-validation",))
    # consensus = 8/10 = 0.8; untrusted .8, unknown .4
    assert ranked[0].site.path == "a.py" and ranked[0].rank_score == 0.8
    assert ranked[1].site.path == "b.py" and ranked[1].rank_score == 0.4


def test_cross_consensus_ordering():
    # consensus .6 untrusted beats consensus 1.0 unknown
    r = _run(
        [_site(line=i, guarded=True, gid="m:A") for i in range(5)]
        + [_site(line=9, exposure="untrusted")],
        threshold=0.5,
    )
    c = r["input-validation"].candidates[0]
    assert c.rank_score == round(5 / 6 * 1.0, 3)


def test_sibling_count_cap_three():
    sites = [_site(line=i, guarded=True, gid="membership:A") for i in range(8)]
    sites += [_site(line=99)]
    r = _run(sites)["input-validation"]
    assert len(r.candidates[0].siblings) == 3


def test_tier_and_group_consensus():
    # emitting group: 8/10 conforming -> unguarded emits as outlier,
    # divergent-guarded emits as watch; sub-bar group emits nothing.
    sites = [_site(group="g1", line=i, guarded=True, gid="m:A") for i in range(8)]
    sites += [_site(group="g1", line=50)]                       # unguarded
    sites += [_site(group="g1", line=51, guarded=True, gid="type:B")]  # divergent shape
    sites += [_site(group="g2", line=80 + i, guarded=True, gid="m:C") for i in range(2)]
    sites += [_site(group="g2", line=100 + i) for i in range(8)]
    res = _run(sites)["input-validation"]
    assert res.status == "active"
    by_line = {c.site.line: c for c in res.candidates}
    assert by_line[50].tier == "outlier"
    assert by_line[51].tier == "watch" and by_line[51].missing_guard == "m:A"
    assert all(c.site.group == "g1" for c in res.candidates)  # g2 is silent


def test_conforming_floor_is_hard():
    # 2 conforming of 3 -> consensus .67 AND floor unmet: silent, no rows
    sites = [_site(group="g1", line=i, guarded=True, gid="m:A") for i in range(2)]
    sites += [_site(group="g1", line=9)]
    res = _run(sites)["input-validation"]
    assert res.status == "no house rule, silent"
    assert res.reason == "too-few-sites"
    assert res.candidates == []
