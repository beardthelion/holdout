# holdout

Static analyzer for Python codebases that learns a project's own defensive habits and ranks the call sites that break them. If a repo checks the environment before seven of its eight `subprocess.run` calls, the eighth is the site holdout reports.

Candidates, not findings. holdout never calls anything a vulnerability.

## Why

Generic rules do not know what a given project considers a guard. holdout learns it from the code: it groups sink calls by `(sink op, argument role, directory)`, finds the guard shape that most of the group uses before the sink, and lists the sites that skip it. The evidence is the project's own consensus, computed deterministically per codebase, with no model in the loop.

## What it checks

Three guard families are implemented:

| Family | Sinks | Guard that conforming sites use |
|---|---|---|
| `input-validation` | `json.loads`, `yaml.load`, `ast.literal_eval`, `open`/`os.path.join`, `subprocess.*` and `os.exec*e` env arguments, URLs passed to `requests`, `httpx`, `aiohttp`, `urllib` | type, shape, allowlist, regex or schema check, or a `sanitize_`/`scrub_`/`filter_`/`clean_` helper |
| `size-cap` | `read`, `recv`, `decompress`, `decode` of unbounded input | a length or size check, or a cap keyword such as `max_size` or `limit` |
| `auth-check` | bodies of route, tool, RPC and command handlers | an authn or authz check |

A group only produces candidates when at least `--site-floor` (default 5) conforming sites share one guard shape covering at least `--threshold` (default 0.8) of the group. Below that there is no house rule and the family stays silent. Unguarded sites are reported as `outlier`; sites guarded with a different shape are reported as `watch`. Vendored, generated and test trees are excluded from both consensus and candidates. [SPEC.md](SPEC.md) lists further families that are designed but not implemented.

## Install

Python 3.10 or newer, no runtime dependencies.

```bash
git clone https://github.com/beardthelion/holdout
cd holdout
python -m venv .venv && .venv/bin/pip install -e '.[dev]'
.venv/bin/holdout --help
```

## Usage

```bash
holdout <repo-root> --out out.jsonl \
  [--families input-validation,size-cap,auth-check] \
  [--threshold 0.8] [--caller-depth 2] [--site-floor 5] \
  [--exposure-file exposure.json] [--also-md]
```

`--also-md` writes a human-readable sidecar next to the JSONL. Exposure (`untrusted`, `internal`, `unknown`) per function comes from `--exposure-file` (a JSON map) or, when that is not given, from `<repo-root>/.clawpatch/scope-boundary.md` lines of the form `- path/to/file.py:function TAINT: yes [entry=POST /api/x]`. A malformed or oversized scope file is ignored with a warning.

Example on the bundled fixture:

```
$ holdout tests/fixtures/env-scrub-house --out out.jsonl --also-md
families=3 active=1 silent=2 candidates=1
```

## Output

Newline-delimited JSON with three row types:

- `family`: one per family, with `status` (`active` or silent), site and guarded counts, consensus ratio, and the reason a family is silent (for example `too-few-sites`)
- `parse_error`: one per file that could not be parsed
- `candidate`: a site that breaks a house rule, with the sink (path, function, line, operation), `missing_guard`, `tier` (`outlier` or `watch`), group consensus, `rank_score`, `exposure`, and conforming `siblings` to compare against

A candidate row from the example above:

```json
{"type": "candidate", "family": "input-validation", "tier": "outlier",
 "sink": {"path": "runner_bad.py", "function": "run_experiment", "line": 9, "operation": "subprocess.run"},
 "missing_guard": "membership:_SAFE_ENV_BLOCKLIST", "group_consensus": 0.857, "rank_score": 0.429,
 "exposure": "unknown", "siblings": [{"path": "runner_local.py", "function": "run_build", "line": 21}, "..."]}
```

## Tests and known-answer gate

```bash
.venv/bin/pytest -q
.venv/bin/python scripts/run_gate.py
```

The gate's pass-gated legs run on vendored fixtures in `tests/fixtures/` and need the expected site in the top 10. Real-repo legs run only when their environment variable points at a checkout and are recorded for information:

```bash
HOLDOUT_MCP_VULN_ROOT=/path/to/mcp-atlassian-checkout .venv/bin/python scripts/run_gate.py
```

Results land in `docs/gate-results.md`. [VERDICT.md](VERDICT.md) has real-target numbers.

## Limitations

- Python only.
- Low yield on large real trees: on the public projects measured in VERDICT.md, no candidate survived a code read as a real missing guard. Treat output as cheap triage leads.
- Guard binding is lexical and operand-based. It cannot tell a real trust boundary from a coincidental one, so defensible variations show up as `watch`.
- A project whose only convention is try/except shows no guard shape, so its sites count as unguarded and never form a consensus.
- Caller walking stops at `--caller-depth` (default 2), and sanitizer resolution is same-module.

## Related tools

- [guard-archaeology](https://github.com/beardthelion/guard-archaeology): finds guards a project added and later lost, using git history instead of consensus
- [path-guard-audit](https://github.com/beardthelion/path-guard-audit) and [ssrf-guard-audit](https://github.com/beardthelion/ssrf-guard-audit): class-specific guard-completeness audits
- [autocatalytic-harness](https://github.com/beardthelion/autocatalytic-harness): the audit harness that writes the `scope-boundary.md` file holdout reads

## License

MIT. See [LICENSE](LICENSE).
