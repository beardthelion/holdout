"""Emit JSONL rows and optional markdown; atomic writes."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile


def _site_id(site) -> str:
    key = f"{site.family}|{site.path}|{site.function}|{site.line}"
    return f"holdout-{site.family}-{hashlib.sha256(key.encode()).hexdigest()[:10]}"


def build_rows(results: dict, considered: tuple, threshold: float,
               ranked: list, parse_errors: list, exclusions: dict) -> list:
    rows = []
    for fam in considered:
        r = results[fam]
        rows.append(
            {
                "type": "family",
                "family": fam,
                "sites": r.sites,
                "guarded": r.guarded,
                "consensus": r.consensus if r.consensus is None else round(r.consensus, 3),
                "threshold": threshold,
                "status": r.status,
                "reason": r.reason,
            }
        )
    for c in ranked:
        s = c.site
        rows.append(
            {
                "type": "candidate",
                "id": _site_id(s),
                "family": s.family,
                "sink": {
                    "path": s.path,
                    "function": s.function,
                    "line": s.line,
                    "operation": s.operation,
                },
                "missing_guard": c.missing_guard,
                "consensus": {"guarded": results[s.family].guarded,
                              "total": results[s.family].sites},
                "group_consensus": c.group_consensus,
                "group_total": c.group_total,
                "tier": c.tier,
                "exposure": s.exposure,
                "rank_score": c.rank_score,
                "siblings": [
                    {"path": b.path, "function": b.function, "line": b.line}
                    for b in c.siblings
                ],
                "entry": s.entry,
            }
        )
    for e in parse_errors:
        rows.append({"type": "parse_error", "path": e.path, "error": e.error})
    if exclusions.get("files") or exclusions.get("dirs") or exclusions.get("by_marker"):
        rows.append(
            {
                "type": "exclusions",
                "files": exclusions.get("files", 0),
                "dirs": exclusions.get("dirs", 0),
                "by_marker": dict(sorted(exclusions.get("by_marker", {}).items())),
            }
        )
    return rows


def _md_clean(s) -> str:
    """Strip control characters from a value before markdown interpolation —
    repo filenames are untrusted input (a newline in a path could inject a
    forged report line)."""
    return "".join(c if c >= " " else " " for c in str(s)).replace("`", "'")


def render_markdown(results: dict, considered: tuple, ranked: list) -> str:
    lines = ["# Holdout candidates", ""]
    for fam in considered:
        r = results[fam]
        if not r.candidates:
            continue
        note = "" if r.status == "active" else f" ({r.reason})"
        lines.append(f"## {fam}{note}")
        lines.append("")
        fam_cands = [c for c in ranked if c.site.family == fam]
        for i, c in enumerate(fam_cands, 1):
            s = c.site
            tag = "" if c.tier == "outlier" else f" [{c.tier}]"
            lines.append(
                f"{i}. `{_md_clean(s.path)}:{_md_clean(s.function)}:{s.line}` "
                f"({_md_clean(s.operation)}) — missing `{_md_clean(c.missing_guard)}`; "
                f"exposure={s.exposure}, score={c.rank_score:.3f}{tag}"
            )
        lines.append("")
    silent = [fam for fam in considered if results[fam].status != "active"]
    lines.append("## Silent families")
    lines.append("")
    for fam in silent:
        r = results[fam]
        lines.append(f"- `{fam}` — {r.reason}")
    lines.append("")
    return "\n".join(lines)


def _atomic_write(path: str, text: str) -> None:
    d = os.path.dirname(os.path.abspath(path))
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".holdout-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def write_outputs(rows: list, out_path: str, also_md_path: str = None,
                  md_text: str = None) -> None:
    text = "".join(json.dumps(r, sort_keys=True) + "\n" for r in rows)
    _atomic_write(out_path, text)
    if also_md_path is not None:
        _atomic_write(also_md_path, md_text or "")
