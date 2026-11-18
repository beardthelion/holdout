# Holdout: inside-out missing-guard finder

## Problem

Most analyzers work outside-in. Taint rules say what a guard should look
like. Variant rules encode a known CVE's guard. Neither can
see a missing guard that has no known pattern, and universal rules drown in
house style.

Holdout works inside-out. For each sink family it catalogs every call site
and which guard precedes it, then ranks the outliers: the sites missing the
guard that the rest of the project treats as mandatory. The pattern is the
project's own consensus, learned per codebase, deterministically. When 47 of
48 call sites validate before the sink and one does not, that is not a
heuristic smell. It is the project's developers testifying the guard belongs
there, and the one site is the testimony's exception.

Candidates, not findings. Holdout never calls anything a vulnerability.

## Core design

The ranking is counted and deterministic. Silence over noise: a family with no
house rule stays silent rather than invent one.

### Sink families

Families come from guard classes seen in real CVE fixes. Per language, a family
is a set of sink operations plus the guard shapes that belong before them.

| Family | Sink operations (examples) | Guard shapes that belong before them |
|---|---|---|
| size-cap | read, recv, decompress, decode of unbounded input | length / size / budget check against a constant or config |
| input-validation | parse, loads, from_string, path join into filesystem | type / shape / allowlist / regex / schema check |
| type-range-check | int cast into index, offset, length, enum | bounds / range / enum membership check |
| allowlist | dispatch by name, plugin load, method call by string | membership in a fixed set or map |
| auth-check | privileged RPC / admin route / secret-bearing call | authn / authz / capability check on the caller |
| escaping | HTML / shell / SQL / template render of untrusted bytes | encode / escape / parameterized API |
| symlink/TOCTOU | open / rename / unlink on a user-influenced path | O_NOFOLLOW, realpath-then-compare, or equivalent |

v1 ships only the first three that pay most often: `input-validation`,
`size-cap`, `auth-check`. The table above is the full family list the tool
is designed around; later versions add the rest without changing the output
shape.

Equivalent guard identities inside one family are normalized to one name
(for example `len(x) < N`, `x.__len__() < N`, and a named `check_size(x)`
helper that does the same thing all count as `size-cap`). Without that
normalization, house style variance invents fake outliers.

### Per-site record

For every call site in a family, record:

- sink: `file:function:line` and the sink operation
- guard_present: true / false (after the caller-chain check below)
- guard_identity: normalized name when present, else null
- exposure: `untrusted` | `internal` | `unknown`

Exposure uses an attack-surface note when one exists
(`.clawpatch/scope-boundary.md` entry points marked `TAINT: yes` map to
`untrusted`). Sites with no surface data stay `unknown`. Unknown is never
assumed to be untrusted or internal; it is its own bucket and ranks below
`untrusted`.

### Consensus

Per family:

    consensus = guarded_sites / total_sites

Default threshold: 0.8 (configurable). A family under the threshold has no
house rule. Holdout writes a header line saying so and emits no candidates
for that family. Silence over noise. An empty candidate list with a
`no house rule, silent` header means checked, not skipped. An empty file
with no headers means the run did not happen.

Sites in generated or vendored paths do not count toward the project's
consensus. See Failure modes.

### Bounded caller-chain check (mandatory)

A guard can live in the caller instead of beside the sink. Before a site
counts as unguarded, Holdout walks the immediate caller chain up to a
configurable depth (default 2) and accepts a matching guard found there.

This check is not optional. Without it the false-positive rate kills trust
in the ranking on the first real run. Depth 0 (sink only) is supported for
debugging but is not a default and must be set explicitly.

### Ranking

    rank_score = consensus_strength * exposure_weight

Where `consensus_strength` is the family's consensus (guarded/total), and
`exposure_weight` is `untrusted=1.0`, `unknown=0.5`, `internal=0.25`.
Higher score ranks first. Ties break by sink path then line number, so the
order is stable across runs.

Each candidate names:

- family
- sink `file:function:line`
- missing guard (normalized identity the siblings share)
- consensus `k/n`
- exposure bucket
- three guarded sibling sites (file:function:line) as the evidence of the
  house rule

If fewer than three guarded siblings exist, list all of them. A family that
passed the threshold with fewer than three guarded sites is still ranked;
the short sibling list is part of the evidence, not a failure.

### Output

Primary: `.clawpatch/holdout.jsonl` next to `.clawpatch/scope-boundary.md`.
Optional: `.clawpatch/holdout.md` rendered from the same rows for humans.

JSONL is the drain format. Rows are siblings-shaped so downstream triage
tooling can consume them unchanged. Holdout itself does not write findings
and does not mark triage verdicts.

#### Header lines (one per family considered)

```json
{"type":"family","family":"input-validation","sites":48,"guarded":47,"consensus":0.979,"threshold":0.8,"status":"active"}
{"type":"family","family":"size-cap","sites":12,"guarded":7,"consensus":0.583,"threshold":0.8,"status":"no house rule, silent"}
```

`status` is `active` or `no house rule, silent`. Every family in the run
emits exactly one header, including silent ones.

#### Candidate rows (only for active families)

```json
{
  "type": "candidate",
  "id": "holdout-<family>-<shortsha>",
  "family": "input-validation",
  "sink": {
    "path": "pkg/handlers/upload.py",
    "function": "handle_upload",
    "line": 142,
    "operation": "json.loads"
  },
  "missing_guard": "input-validation",
  "consensus": {"guarded": 47, "total": 48},
  "exposure": "untrusted",
  "rank_score": 0.979,
  "siblings": [
    {"path": "pkg/handlers/create.py", "function": "handle_create", "line": 88},
    {"path": "pkg/handlers/update.py", "function": "handle_update", "line": 101},
    {"path": "pkg/api/parse.py", "function": "parse_body", "line": 40}
  ],
  "entry": null
}
```

`entry` is optional. When known (from the scope note or an
`--exposure-file`), it is the HTTP/RPC route or entry-point id that reaches
this sink. Used for the runtime handoff below. Null when unknown.

`id` is stable for a given `(family, sink.path, sink.function, sink.line)`
so re-runs produce the same id.

Optional markdown render is one section per active family, ranked
candidates as a numbered list, silent families listed once under a
"Silent families" heading. No severity, no "vulnerability" wording.

## Workflow placement

Run early, beside an attack-surface note (`scope-boundary.md`).

- The scope note says where the surface is.
- Holdout says where the surface breaks its own rules.
- A reviewer may cite Holdout rows as evidence ("the notes call X guarded;
  Holdout shows 1/48 unguarded"). Holdout is counted, deterministic
  evidence, not judgment, so the ranking stays diffable run to run.

Candidates go to manual triage with the attacker/victim pair named from the
exposure data. A candidate becomes a finding only with a proven end-to-end
PoC. Holdout ranks; it does not acquit and it does not file.

### Runtime handoff

On source-available targets, a candidate with a non-null `entry` that is an
HTTP or RPC route can be handed to a runtime taint tracer: plant at the
entry, watch the sink. A runtime confirm or kill closes the candidate
without hand-debugging. Unmappable entries stay in the manual queue.

## v1 scope

- Language: Python only (stdlib `ast`, or `libcst` if concrete syntax helps
  the caller-chain walk). Deterministic. No network.
- Families: `input-validation`, `size-cap`, `auth-check`.
- Bounded caller-chain check, default depth 2.
- Siblings-shaped JSONL output as specified above.
- Exposure may be operator-supplied via `--exposure-file` (a simple map of
  `path:function -> untrusted|internal|unknown`, or a list of untrusted
  entry files). Built reachability is out of scope for v1; when no
  exposure file is given every site is `unknown`.

### CLI

```
holdout <repo-root> --out <path> \
  [--families input-validation,size-cap,auth-check] \
  [--threshold 0.8] \
  [--caller-depth 2] \
  [--exposure-file <path>] \
  [--also-md]
```

- `--out` is the JSONL path (typically `.clawpatch/holdout.jsonl`).
- `--also-md` writes the sibling `.md` next to it.
- Exit 0 on success, including the all-silent case. Nonzero only on tool
  failure (unreadable root, bad flag, parse abort).
- Stdout: one-line summary `families=N active=A silent=S candidates=C`.

### Package layout (suggested)

```
holdout/
  pyproject.toml
  README.md
  SPEC.md
  src/holdout/
    __init__.py
    cli.py
    scan.py          # walk + per-site records
    families.py      # sink ops + guard shapes per family
    consensus.py     # scores, threshold, rank
    callers.py       # bounded caller-chain walk
    exclude.py       # vendored / generated path markers
    emit.py          # JSONL + optional MD
  tests/
```

Keep it small. No plugin system, no config file beyond CLI flags, no
auto-update of family definitions from an external corpus in v1 (hand-maintain
`families.py` against the table above).

## Validation gate

Must pass before trusting Holdout on any new target. Fail means kill the
tool or redesign; do not widen the corpus to hide a miss.

### Known-answer cases

The pass-gated legs are vendored fixtures under `tests/fixtures/`, so the
gate is deterministic on any machine:

- `env-scrub-house`: a set of subprocess call sites that all pass the
  environment through a house scrub helper, plus one site that passes the
  raw environment. The raw site must rank top of its family.
- `auth-house`: a set of mutating POST handlers that all call the house
  authz helper, plus one that does not. The unguarded handler must rank top
  of its family.
- Negative control: `env-scrub-house` with the non-conforming file removed
  must emit zero candidates.

Pass: each expected site ranks in the top 10 candidates of the run (or top
of its family if the run emits fewer than 10 total). Fail: kill or redesign
before any other target.

Real-repo legs (for example the public mcp-atlassian SSRF,
CVE-2026-27826) run only when the operator points an env var at a local
checkout. They are recorded informationally and never pass-gate.

### How to run the gate

```
python scripts/run_gate.py
```

Or by hand on any checkout:

```
holdout <repo-root> --out out.jsonl \
  --families input-validation,size-cap,auth-check \
  --caller-depth 2
```

Inspect the JSONL. Confirm the known site appears as a `type=candidate` row
with the right family and a rank_score that puts it in the top 10. Confirm
silent families emitted a header and no candidates. Confirm re-running
produces the same ids and order.

## Out of scope for v1

- Languages other than Python.
- Full interprocedural reachability / automatic exposure inference.
- Auto-filing, auto-drafting, or calling anything a vulnerability.
- Autofix or patch suggestions.
- Pulling family definitions live from an external corpus.
- PDF / email / websocket-specific sink packs.
- Replacing taint analysis, runtime tracing, or attack-surface notes.

## Failure modes

Design against these; each has a concrete mitigation in v1.

1. **Vendored / generated pollution.** Generated and vendored code pollutes
   consensus counts. Exclude by path markers (`vendor/`, `third_party/`,
   `node_modules/`, `.tox/`, `venv/`, `site-packages/`, `*_pb2.py`,
   `*.generated.py`, and a small configurable list). Count a vendored tree
   as its own codebase only if the operator points Holdout at it as the
   repo-root; never mix it into the parent project's consensus.

2. **Guard lives in the caller.** Bounded caller-chain check (default depth
   2) before a site counts as unguarded. See Core design. Depth is the
   main false-positive dial.

3. **Deliberate exceptions.** A site is unguarded because the input is
   provably internal. That is what manual triage is for. Holdout's job
   is the ranking, not the acquittal. Exposure `internal` lowers rank but
   does not suppress the candidate.

4. **House style variance.** Multiple equivalent guard identities inside
   one family must normalize to one name, or consensus shatters into
   false outliers. Maintain a small synonym map per family in
   `families.py`.

5. **Threshold too low or too high.** 0.8 is the default, not a law. If a
   mature codebase guards 95%+ and a young one guards 60%, operators set
   `--threshold` per target. Never invent a house rule for a family under
   threshold.

6. **Empty or tiny families.** A family with fewer than 5 sites cannot
   claim a house rule even when consensus is 1.0. Emit `no house rule,
   silent` with reason `too-few-sites`. Configurable via a hard floor
   (default 5).
