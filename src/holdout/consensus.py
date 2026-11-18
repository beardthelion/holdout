"""Consensus, threshold/floor, ranking.

Real silence (post-audit semantics): a (family, sink-op + arg-role group)
emits candidates ONLY when its conforming count reaches the site floor
(default 5) AND conforming/total reaches the threshold (default 0.8).
Anything below that has no house rule and emits zero rows — headers still
report the family's status honestly either way.

Inside an emitting group: unguarded sites are `outlier` tier, sites guarded
with a divergent identity are `watch` tier. rank_score = group consensus x
exposure weight.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

EXPOSURE_WEIGHTS = {"untrusted": 1.0, "unknown": 0.5, "internal": 0.25}

REASON_BELOW = "below-threshold"
REASON_FEW = "too-few-sites"


@dataclass
class FamilyResult:
    family: str
    sites: int  # cataloged sites
    guarded: int  # conforming sites (dominant identity of an emitting group)
    consensus: Optional[float]
    status: str  # "active" | "no house rule, silent"
    reason: Optional[str]
    candidates: list = field(default_factory=list)


@dataclass
class Candidate:
    site: object  # scan.Site
    missing_guard: str
    rank_score: float
    siblings: list
    tier: str = "outlier"  # "outlier" (unguarded) | "watch" (divergent guard)
    group_consensus: float = 0.0
    group_total: int = 0


def dominant_identity(group_sites: list) -> Optional[str]:
    """Most common guard identity among guarded sites; ties -> sorted first."""
    counts = {}
    for s in group_sites:
        if s.guard_present and s.guard_identity:
            counts[s.guard_identity] = counts.get(s.guard_identity, 0) + 1
    if not counts:
        return None
    return sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[0][0]


def compute(sites: list, considered: tuple, threshold: float, site_floor: int) -> dict:
    """Family -> FamilyResult, in canonical order.

    Groups are (sink op#role, directory scope): a house rule lives in one
    part of the tree. Conformance is at guard-shape granularity — the same
    defensive instinct (membership-filter, type-check, bounds-check) counts
    whatever the operand; the dominant shape+operand is still reported as
    the expected guard.
    """
    results = {}
    for fam in considered:
        fam_sites = [s for s in sites if s.family == fam]
        groups = {}
        for s in fam_sites:
            groups.setdefault((s.group, s.scope), []).append(s)

        emitting = []
        fam_conforming = 0
        any_dominant = False
        best_conforming = 0
        for (group, scope), gsites in sorted(groups.items()):
            guarded = [s for s in gsites if s.guard_present and s.guard_identity]
            if not guarded:
                continue
            any_dominant = True
            # dominant SHAPE = the instinct; dominant identity = the operand
            # expected inside that shape
            shape_counts = {}
            for s in guarded:
                sh = s.guard_identity.split(":", 1)[0]
                shape_counts[sh] = shape_counts.get(sh, 0) + 1
            top_shape = sorted(
                shape_counts.items(), key=lambda kv: (-kv[1], kv[0])
            )[0][0]
            conf = [
                s for s in guarded
                if s.guard_identity.split(":", 1)[0] == top_shape
            ]
            op_counts = {}
            for s in conf:
                op_counts[s.guard_identity] = op_counts.get(s.guard_identity, 0) + 1
            dom = sorted(op_counts.items(), key=lambda kv: (-kv[1], kv[0]))[0][0]
            best_conforming = max(best_conforming, len(conf))
            fam_conforming += len(conf)
            g_total = len(gsites)
            g_consensus = len(conf) / g_total
            if len(conf) >= site_floor and g_consensus >= threshold:
                emitting.append((group, dom, conf, gsites, g_consensus))

        cataloged = len(fam_sites)
        if not any_dominant or cataloged == 0:
            results[fam] = FamilyResult(
                fam, cataloged, 0, None, "no house rule, silent", REASON_FEW
            )
            continue
        if not emitting:
            reason = REASON_FEW if best_conforming < site_floor else REASON_BELOW
            results[fam] = FamilyResult(
                fam, cataloged, fam_conforming,
                fam_conforming / cataloged, "no house rule, silent", reason,
            )
            continue

        # active: consensus over emitting groups only, so status and number agree
        em_total = sum(len(g[3]) for g in emitting)
        em_conf = sum(len(g[2]) for g in emitting)
        res = FamilyResult(
            fam, cataloged, em_conf, em_conf / em_total, "active", None
        )
        all_conf = []
        for group, dom, conf, gsites, g_consensus in emitting:
            all_conf.extend(conf)
            for s in gsites:
                if s in conf:
                    continue
                sibs = sorted(conf, key=lambda c: (c.path, c.function, c.line))[:3]
                res.candidates.append(
                    Candidate(
                        site=s,
                        missing_guard=dom,
                        rank_score=round(
                            g_consensus * EXPOSURE_WEIGHTS[s.exposure], 3
                        ),
                        siblings=sibs,
                        tier="watch" if s.guard_present else "outlier",
                        group_consensus=round(g_consensus, 3),
                        group_total=g_total,
                    )
                )
        results[fam] = res
    return results


def rank_candidates(results: dict, considered: tuple) -> list:
    """All emitted candidates, globally ranked."""
    cands = [c for fam in considered for c in results[fam].candidates]
    return sorted(
        cands, key=lambda c: (-c.rank_score, c.site.path, c.site.line, c.site.function)
    )
