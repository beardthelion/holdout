# Gate results

## env-scrub fixture
- expected: runner_bad.py:run_experiment
- emitted_total: 1
- observed_ordinal: 0
- observed_family_ordinal: 0
- note: bar=top-of-family ordinal=0 fam_ordinal=0
- verdict: pass

## auth-check fixture
- expected: server.py:start_export_job
- emitted_total: 1
- observed_ordinal: 0
- observed_family_ordinal: 0
- note: bar=top-of-family ordinal=0 fam_ordinal=0
- verdict: pass

## env-scrub conforming-only negative control
- note: candidates emitted: 0
- verdict: pass

## mcp-atlassian SSRF
- expected: src/mcp_atlassian/servers/dependencies.py:None
- emitted_total: 0
- note: expected site not emitted
- verdict: informational
