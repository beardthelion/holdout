"""Cross-function machinery: def index, sanitizer form, caller walk.

One owner for the shared def index (KTD13) used by both the
sanitizer-assignment guard form (KTD3) and the bounded caller-chain
check (R6/KTD9).
"""

from __future__ import annotations

import ast
from typing import Optional

from . import families
from .scan import (
    ModuleInfo,
    _leaf_names,
    dotted_of,
    frame_node_of,
    frame_provenance,
    guards_for_frame,
    modpath_for,
    resolve_dotted,
    root_names,
)


def _prov_for(info: ModuleInfo, fnode) -> dict:
    key = id(fnode)
    if key not in info.prov_cache:
        info.prov_cache[key] = frame_provenance(fnode.body)
    return info.prov_cache[key]


def build_def_index(modules: dict) -> dict:
    """(modpath, qualname) -> FunctionDef node."""
    idx = {}
    for modpath, info in modules.items():
        for qn, node in info.defs.items():
            idx[(modpath, qn)] = node
    return idx


def resolve_callee(info: ModuleInfo, call: ast.Call, modules: dict) -> Optional[tuple]:
    """Resolve a call to (modpath, qualname) inside the analyzed tree.

    Same-module defs, imported names (import map), and ClassName.method
    attribute calls on self/class receivers. Returns None when unresolvable;
    callers degrade to sink-only analysis rather than guessing.
    """
    dotted = resolve_dotted(call.func, info.importmap) or dotted_of(call.func)
    if not dotted:
        return None

    parts = dotted.split(".")

    # Try longest module-prefix match against known modules.
    for i in range(len(parts), 0, -1):
        mod = ".".join(parts[:i])
        if mod in modules and len(parts) > i:
            qn = ".".join(parts[i:])
            return (mod, qn)
        if mod in modules and i == len(parts):
            return (mod, "<module>")

    # Same-module defs: bare-Name calls or full dotted only — never a bare
    # basename tail on an attribute call (x.y() must not merge into local y()).
    mp = info.modpath
    if dotted in info.defs:
        return (mp, dotted)
    return None


def resolve_self_call(info: ModuleInfo, call: ast.Call, frame_qn: str) -> Optional[tuple]:
    """`self.m()` / `ClassName.m()` inside module -> (modpath, Class.m)."""
    d = dotted_of(call.func)
    if not d:
        return None
    parts = d.split(".")
    if parts[0] == "self" and "." in frame_qn:
        cls = frame_qn.rsplit(".", 1)[0]
        qn = ".".join([cls] + parts[1:])
        if qn in info.defs:
            return (info.modpath, qn)
    if len(parts) >= 2:
        for cand in (".".join(parts[:2]), ".".join(parts)):
            if cand in info.defs:
                return (info.modpath, cand)
    return None


def _callee_key(info: ModuleInfo, call: ast.Call, frame_qn: str, modules: dict) -> Optional[tuple]:
    return resolve_self_call(info, call, frame_qn) or resolve_callee(info, call, modules)


def build_callers(modules: dict) -> dict:
    """callee (modpath, qualname) -> [(caller_modpath, caller_qualname, call)]."""
    edges = {}
    for mp, info in modules.items():
        for frame_qn, call in info.calls:
            key = _callee_key(info, call, frame_qn, modules)
            if key is not None:
                edges.setdefault(key, []).append((mp, frame_qn, call))
    return edges


def _func_params(fnode) -> list:
    a = fnode.args
    return [x.arg for x in (a.posonlyargs + a.args + a.kwonlyargs)] + [
        x.arg for x in (a.vararg, a.kwarg) if x
    ]


def _sanitizer_guard(info: ModuleInfo, site, modules: dict, defindex: dict,
                     callee_cache: dict, hops: int = 2) -> Optional[str]:
    """Sanitizer form: name assigned from f(...) where f's body guards.

    Walks frame assignments; for each sink-bound name produced by a call to
    a resolvable def, runs the shared predicate on the callee body. Follows
    one nested call hop so a wrapper around the real scrub still counts.
    """
    frame = frame_node_of(info, site.function)
    if frame is None:
        return None
    stmts = frame.body if isinstance(frame, (ast.FunctionDef, ast.AsyncFunctionDef)) else frame
    assigns = list(_iter_assignments(stmts))

    def callee_guard(key, depth, visited=None):
        """Prefer the deepest resolvable guard identity inside the callee
        chain so direct and wrapped sanitizers collapse to one operand."""
        cache_key = (key, site.family)
        if depth <= 0 or key in (visited or ()):
            return None
        if cache_key not in callee_cache:
            visited = (visited or ()) + (key,)
            cinfo = modules[key[0]]
            fnode = defindex[key]
            gs = guards_for_frame(cinfo, key[1], site.family)
            # operand binding: prefer a guard that binds a callee parameter
            # (the param receiving the sink-flowing argument counts via the
            # weak form — any param).
            params = set(_func_params(fnode))
            bound = [g for g in gs if "*" in g.bound or _leaf_names(g.bound) & params]
            gs = bound or gs
            # follow check/sanitizer-named calls first for deepest identity
            got = None
            for ch in ast.walk(fnode):
                if isinstance(ch, ast.Call):
                    d = dotted_of(ch.func) or ""
                    if families.is_check_name(d) or families.is_sanitizer_name(d):
                        nk = _callee_key(cinfo, ch, key[1], modules)
                        if nk and nk in defindex:
                            got = callee_guard(nk, depth - 1, visited)
                            if got:
                                break
            callee_cache[cache_key] = got or (
                sorted(gs, key=lambda g: g.identity)[0].identity if gs else None
            )
        return callee_cache[cache_key]

    site_heads = {n.split(".")[0] for n in site.arg_names}
    # inline sanitizer form: sink(env=f(x)) — the arg is itself a call
    for expr in getattr(site, "arg_exprs", ()):
        if not isinstance(expr, ast.Call):
            continue
        key = _callee_key(info, expr, site.function, modules)
        if key and key in defindex:
            got = callee_guard(key, hops)
            if got:
                return got
    for st in assigns:
        if not isinstance(st.value, ast.Call):
            continue
        targets = st.targets if isinstance(st, ast.Assign) else [st.target]
        names = {n.split(".")[0] for t in targets for n in root_names(t)}
        if not (names & site_heads):
            continue
        key = _callee_key(info, st.value, site.function, modules)
        if key and key in defindex:
            got = callee_guard(key, hops)
            if got:
                return got
    return None


def _iter_assignments(stmts):
    for st in stmts:
        if isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for node in ast.walk(st):
            if isinstance(node, (ast.Assign, ast.AnnAssign)) and getattr(node, "value", None) is not None:
                yield node


def apply_caller_walk(sites: list, modules: dict, depth: int) -> None:
    """Bound caller-chain check + sanitizer form for still-unguarded sites."""
    if not sites:
        return
    defindex = build_def_index(modules)
    edges = build_callers(modules)
    callee_cache = {}

    for site in sites:
        info = modules.get(modpath_for(site.path))
        if info is None:
            continue
        # also re-resolve sites already marked by a bare check:name identity so
        # wrapped and direct sanitizers share the deepest operand identity
        if site.guard_present and not site.guard_identity.startswith("check:"):
            continue
        try:
            got = _sanitizer_guard(info, site, modules, defindex, callee_cache)
        except RecursionError:
            got = None
        if got:
            site.guard_present = True
            site.guard_identity = got
            continue
        if site.guard_present or depth <= 0:
            continue
        try:
            _walk_callers(site, info, modules, edges, defindex, depth)
        except RecursionError:
            continue  # deep caller tree degrades to unguarded, not a crash


def _walk_callers(site, info, modules, edges, defindex, depth) -> None:
    """BFS callers; a bound guard in ANY caller within depth clears the site."""
    fnode = info.defs.get(site.function)
    if fnode is None:
        return
    prov = _prov_for(info, fnode)
    bound = set()
    for n in site.arg_names:
        bound |= prov.get(n.split(".")[0], set()) | {n.split(".")[0]}
    required_params = [p for p in _func_params(fnode) if p.split(".")[0] in bound]
    if not required_params:
        required_params = _func_params(fnode)  # weak form: any param

    visited = {(info.modpath, site.function)}
    frontier = [(info.modpath, site.function)]
    for _ in range(depth):
        nxt = []
        for key in frontier:
            for caller_mp, caller_qn, call in edges.get(key, []):
                ckey = (caller_mp, caller_qn)
                if ckey in visited:
                    continue
                visited.add(ckey)
                nxt.append(ckey)
                cinfo = modules.get(caller_mp)
                if cinfo is None:
                    continue
                req_names = set()
                params = _func_params(fnode)
                for i, argexpr in enumerate(call.args):
                    if i < len(params) and params[i] in required_params:
                        req_names |= {n.split(".")[0] for n in root_names(argexpr)}
                for kw in call.keywords:
                    if kw.arg in required_params:
                        req_names |= {n.split(".")[0] for n in root_names(kw.value)}
                if not req_names:
                    req_names = bound
                for g in guards_for_frame(cinfo, caller_qn, site.family):
                    if "*" in g.bound or _leaf_names(g.bound) & req_names:
                        site.guard_present = True
                        site.guard_identity = g.identity
                        return
        frontier = nxt
        if not frontier:
            return
