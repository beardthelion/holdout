# Verdict: Holdout v1 usefulness audit rework

## Semantics now

A group is `(sink op, argument role, directory)`. It emits candidates only
when at least `--site-floor` (5) sites conform to one guard shape covering
`--threshold` (0.8) of the group. Below the bar: zero rows, honest silence.
Unguarded sites are `outlier`; sites guarded with a different instinct are
`watch`. `missing_guard` names the dominant operand. Siblings are same-group
conforming sites only.

## Gate (scripts/run_gate.py)

Pass-gated legs are vendored fixtures under `tests/fixtures/`, so the gate
runs green on any box under the restored top-10 rule:

- env-scrub fixture: pass (expected site ordinal 0)
- auth-check fixture: pass (ordinal 0)
- conforming-only negative control: pass (0 candidates)

Real-repo legs run under env vars and are recorded informationally. On
the real trees measured, the expected sites were cataloged but their
groups did not reach 0.8 consensus, so they emitted nothing. That is the
honest outcome on those trees, not a gate failure.

## Re-run numbers (public OSS targets)

| target | size-cap | input-validation | auth-check | candidates | wall |
|---|---|---|---|---|---|
| NousResearch/hermes-agent | silent 0.27 | active 0.95 | silent 0.13 | 2 (1 outlier, 1 watch) | 12s |
| Chia-Network/chia-blockchain | silent 0.17 | silent 0.28 | silent 0.10 | 0 | 4s |
| sooperset/mcp-atlassian (pre-fix for CVE-2026-27826) | silent (0 sites) | silent 0.10 | silent 0.15 | 0 | 1s |

The two hermes-agent candidates read as defensible on a code read (a
different but adequate guard instinct at a different trust boundary), not
missing guards. They are correctly reported as watch/outlier with correct
siblings.

## Usefulness grade

Low yield on large real trees. The emission rule is honest (silent
families stay silent, ranking is not flat, fixture gate passes), but on
the targets above it produced no candidate that survived a code read as a
real missing guard. Treat output as cheap triage leads, never findings.

## Known limits

- Guard binding is lexical and operand-based; it cannot tell a real trust
  boundary from a coincidental one. Divergent-but-defensible sites will
  appear as watch.
- A repo where the convention is try/except alone (no shape check) shows no
  guard shape at all; those sites are counted unguarded, which keeps them
  out of consensus and out of candidates.
- Caller-walk depth 2 and same-module sanitizer resolution bound what counts
  as guarded.
