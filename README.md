# Holdout

Source-code analyzer that mines a target's own defensive habits and ranks
the call sites that break them. Inside-out evidence: the pattern is the
project's consensus, learned per codebase, deterministically.

Candidates, not findings. Holdout never calls anything a vulnerability.

**Status: v1 implemented.** Read [SPEC.md](SPEC.md).

## Run

```bash
python -m venv .venv && .venv/bin/pip install -e .
holdout <repo-root> --out .clawpatch/holdout.jsonl
```

`holdout <repo-root> --out <path>` writes newline-delimited JSON: one
`family` header per family, one `parse_error` row per unparseable file, and
`candidate` rows for sites that break a house rule the repo itself
demonstrates. `--also-md` writes a human-readable sidecar.

A `(sink op, argument role, directory)` group only emits when at least
`--site-floor` (5) conforming sites share a guard shape covering
`--threshold` (0.8) of the group. Below that there is no house rule and the
family stays silent: zero candidate rows. Unguarded sites emit as `outlier`,
sites guarded with a different shape emit as `watch`.

```bash
holdout <repo-root> --out out.jsonl \
  [--families input-validation,size-cap,auth-check] \
  [--threshold 0.8] [--caller-depth 2] [--site-floor 5] \
  [--exposure-file path] [--also-md]
```

## Known-answer gate

```bash
.venv/bin/python scripts/run_gate.py
```

Pass-gated legs run on vendored fixtures in `tests/fixtures/` and need a
top-10 rank for the expected site. Real-repo legs run when their env var
points at a checkout and are recorded informationally:

```bash
HOLDOUT_MCP_VULN_ROOT=/path/to/mcp-atlassian-vuln \
.venv/bin/python scripts/run_gate.py
```

Results land in `docs/gate-results.md`. See `VERDICT.md` for real-target
numbers.
