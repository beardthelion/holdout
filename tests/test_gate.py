"""Gate result check: docs/gate-results.md must exist and record passes.

This test never skips: an absent note or a recorded miss is a non-pass.
The live gate itself is scripts/run_gate.py, run manually against the
pinned checkouts.
"""

import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NOTE = os.path.join(ROOT, "docs", "gate-results.md")


def test_gate_results_present_and_passing():
    assert os.path.isfile(NOTE), "docs/gate-results.md missing — run scripts/run_gate.py"
    text = open(NOTE).read()
    verdicts = re.findall(r"verdict:\s*(\w+)", text)
    assert verdicts, "gate-results.md has no verdict lines"
    gated = [v for v in verdicts if v not in ("informational", "skip")]
    assert gated, "no pass-gated verdicts recorded"
    assert all(v == "pass" for v in gated), "gate-results.md records a miss"
