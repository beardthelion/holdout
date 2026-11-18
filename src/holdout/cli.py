"""CLI entry point: holdout <repo-root> --out <path> [flags]."""

from __future__ import annotations

import argparse
import os
import sys

from . import consensus, emit, exposure, families, scan
from .callers import apply_caller_walk


class HoldoutError(Exception):
    pass


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="holdout",
        description="Inside-out missing-guard finder: rank call sites that "
        "break the target's own defensive consensus.",
    )
    p.add_argument("repo_root", help="target repository root to scan")
    p.add_argument("--out", required=True, help="JSONL output path")
    p.add_argument(
        "--families",
        default=None,
        help="comma-separated subset of families to consider",
    )
    p.add_argument("--threshold", type=float, default=0.8)
    p.add_argument("--caller-depth", type=int, default=2)
    p.add_argument("--site-floor", type=int, default=5)
    p.add_argument("--exposure-file", default=None)
    p.add_argument("--also-md", action="store_true")
    return p


def _fail(msg: str, code: int = 2) -> int:
    print(f"holdout: stopped: {msg}", file=sys.stderr)
    return code


def _parse_args(argv) -> tuple:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.families:
        requested = [f.strip() for f in args.families.split(",") if f.strip()]
        unknown = [f for f in requested if f not in families.FAMILIES]
        if unknown:
            raise HoldoutError(f"unknown families: {', '.join(unknown)}")
        considered = tuple(f for f in families.FAMILIES if f in requested)
    else:
        considered = families.FAMILIES
    if not 0.0 <= args.threshold <= 1.0:
        raise HoldoutError("--threshold must be in [0, 1]")
    if args.caller_depth < 0:
        raise HoldoutError("--caller-depth must be >= 0")
    if args.site_floor < 0:
        raise HoldoutError("--site-floor must be >= 0")
    return args, considered


def run(
    repo_root: str,
    out: str,
    considered: tuple = families.FAMILIES,
    threshold: float = 0.8,
    caller_depth: int = 2,
    site_floor: int = 5,
    exposure_file: str = None,
    also_md: bool = False,
) -> int:
    """Analyze and write outputs; returns 0 or raises HoldoutError."""
    real = os.path.realpath(repo_root)
    if not os.path.isdir(real):
        raise HoldoutError(f"unreadable repo root: {repo_root}")

    res = scan.scan_repo(real)
    if res.files_parsed == 0:
        raise HoldoutError("zero files parsed")

    try:
        emap = exposure.load_exposure(real, exposure_file)
    except exposure.ExposureError as e:
        raise HoldoutError(str(e))
    exposure.apply_exposure(res.sites, emap)

    apply_caller_walk(res.sites, res.modules, caller_depth)

    results = consensus.compute(res.sites, considered, threshold, site_floor)
    ranked = consensus.rank_candidates(results, considered)

    rows = emit.build_rows(
        results,
        considered,
        threshold,
        ranked,
        res.parse_errors,
        {"files": res.excluded_files, "dirs": res.excluded_dirs,
         "by_marker": res.by_marker},
    )
    md_path = os.path.splitext(out)[0] + ".md" if also_md else None
    md_text = emit.render_markdown(results, considered, ranked) if also_md else None
    try:
        emit.write_outputs(rows, out, md_path, md_text)
    except OSError as e:
        raise HoldoutError(f"cannot write output: {e}")

    n_active = sum(1 for f in considered if results[f].status == "active")
    n_silent = len(considered) - n_active
    print(
        f"families={len(considered)} active={n_active} silent={n_silent} "
        f"candidates={len(ranked)}"
    )
    return 0


def main(argv=None) -> int:
    try:
        args, considered = _parse_args(argv)
    except HoldoutError as e:
        return _fail(str(e))
    try:
        return run(
            repo_root=args.repo_root,
            out=args.out,
            considered=considered,
            threshold=args.threshold,
            caller_depth=args.caller_depth,
            site_floor=args.site_floor,
            exposure_file=args.exposure_file,
            also_md=args.also_md,
        )
    except HoldoutError as e:
        return _fail(str(e))


if __name__ == "__main__":
    raise SystemExit(main())
