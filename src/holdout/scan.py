"""Repo walk, per-module AST pass, site records, guard detection.

Owns the walker half (R3/R4), the sink cataloging (R1/R2), the shared
guard predicate `guard_identities_in_frame` (KTD4), and intra-frame
guard classification (R5 first half). Cross-function machinery lives in
callers.py.
"""

from __future__ import annotations

import ast
import os
from dataclasses import dataclass, field
from typing import Iterator, Optional

from . import exclude, families

MAX_FILE_BYTES = 4 * 1024 * 1024  # 4 MiB, mirroring pygraph


@dataclass
class ParseErrorRec:
    path: str
    error: str


@dataclass
class Guard:
    identity: str
    bound: frozenset  # names this guard binds; "*" means frame-wide
    scope: Optional[tuple] = None  # (start,end) lines the guard dominates


@dataclass
class Site:
    family: str
    group: str
    path: str
    function: str
    line: int
    operation: str
    arg_names: frozenset  # sink-bound names incl. provenance closure
    arg_exprs: tuple = ()  # sink arg AST exprs, for inline-call guards
    scope: str = ""  # directory scope; the house rule is per-subsystem
    guard_present: bool = False
    guard_identity: Optional[str] = None
    exposure: str = "unknown"
    entry: Optional[str] = None


@dataclass
class ModuleInfo:
    relpath: str
    modpath: str
    tree: ast.Module
    importmap: dict = field(default_factory=dict)
    defs: dict = field(default_factory=dict)  # qualname -> FunctionDef/AsyncFunctionDef
    calls: list = field(default_factory=list)  # (caller_qualname, ast.Call)
    # per-run memo caches: guard lists and provenance are pure over the AST,
    # so one computation serves every site sharing a frame.
    guard_cache: dict = field(default_factory=dict)
    prov_cache: dict = field(default_factory=dict)


@dataclass
class ScanResult:
    sites: list
    parse_errors: list
    excluded_files: int
    excluded_dirs: int
    files_parsed: int
    modules: dict = field(default_factory=dict)  # modpath -> ModuleInfo
    by_marker: dict = field(default_factory=dict)  # marker class -> count


# --- path / module naming ----------------------------------------------------


def modpath_for(relpath: str) -> str:
    parts = relpath.replace(os.sep, ".").split(".")
    if parts[-1] == "py":
        parts = parts[:-1]
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts) if parts else relpath


def _walk(root: str, state: dict) -> Iterator[tuple[str, str]]:
    """Sorted repo walk honoring exclusions, confinement, and root override.

    ``state`` accumulates exclusion counts; the caller reads it after the
    generator is exhausted so trailing excluded dirs count too.
    """
    real_root = os.path.realpath(root)
    root_excluded = bool(exclude.is_excluded_dir(os.path.basename(real_root)))
    for dirpath, dirnames, filenames in os.walk(real_root, followlinks=False):
        dirnames.sort()
        filenames.sort()
        rel_dir = os.path.relpath(dirpath, real_root)
        if not root_excluded:
            kept = []
            for d in dirnames:
                cls = exclude.is_excluded_dir(d)
                if cls:
                    state["excluded_dirs"] += 1
                    state["by_marker"][cls] = state["by_marker"].get(cls, 0) + 1
                else:
                    kept.append(d)
            dirnames[:] = kept
        for fn in filenames:
            rel = os.path.normpath(os.path.join(rel_dir, fn)) if rel_dir != "." else fn
            cls = "" if root_excluded else exclude.marker_class(rel)
            if cls:
                state["excluded_files"] += 1
                state["by_marker"][cls] = state["by_marker"].get(cls, 0) + 1
                continue
            if not fn.endswith(".py"):
                continue
            abspath = os.path.join(dirpath, fn)
            # Root confinement: a symlinked file resolving outside the root
            # never enters the scan.
            if os.path.islink(abspath) and not os.path.realpath(abspath).startswith(
                real_root + os.sep
            ):
                state["excluded_files"] += 1
                continue
            yield rel, abspath


def _import_map(tree: ast.Module) -> dict:
    m = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.asname:
                    m[a.asname] = a.name
        elif isinstance(node, ast.ImportFrom) and node.module:
            for a in node.names:
                m[a.asname or a.name] = f"{node.module}.{a.name}"
    return m



def dotted_of(node: ast.AST) -> Optional[str]:
    """Best-effort dotted label for a Name/Attribute chain."""
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        parts.reverse()
        return ".".join(parts)
    if isinstance(node, ast.Call):
        return dotted_of(node.func)
    return None


def resolve_dotted(node: ast.AST, importmap: dict) -> Optional[str]:
    d = dotted_of(node)
    if d is None:
        return None
    head = d.split(".")[0]
    if head in importmap:
        rest = d.split(".")[1:]
        return ".".join([importmap[head]] + rest)
    return d


def root_names(expr: ast.AST) -> set:
    """All names and attribute prefixes in an expression (any ctx — targets
    are names too, since guards bind produced names as well as read ones)."""
    out = set()
    for n in ast.walk(expr):
        if isinstance(n, ast.Name):
            out.add(n.id)
        elif isinstance(n, ast.Attribute):
            d = dotted_of(n)
            if d:
                out.add(d)
                out.add(d.split(".")[0])
    return out


def _leaf_names(names) -> set:
    """Drop names that are a strict dotted prefix of a sibling — bare `self`
    or `os` carry no operand identity; `self.x` vs `self.y` must not match."""
    names = set(names)
    return {n for n in names if not any(m.startswith(n + ".") for m in names)}


def _const_or_none(expr: ast.AST) -> bool:
    """Bounded literals: constants and containers of constants."""
    if isinstance(expr, ast.Constant):
        return True
    if isinstance(expr, (ast.List, ast.Tuple, ast.Set)):
        return all(_const_or_none(e) for e in expr.elts)
    if isinstance(expr, ast.Dict):
        return all(_const_or_none(e) for e in expr.keys + expr.values if e)
    return False


# --- name provenance (intra-frame def-use) ----------------------------------


def frame_provenance(stmts: list) -> dict:
    """name -> set of upstream names feeding it (transitive)."""
    direct = {}

    def visit_stmts(body):
        for st in body:
            if isinstance(st, ast.Assign):
                srcs = root_names(st.value)
                for t in st.targets:
                    for name in root_names(t):
                        direct.setdefault(name.split(".")[0], set()).update(srcs)
            elif isinstance(st, (ast.AnnAssign, ast.AugAssign)) and st.value is not None:
                srcs = root_names(st.value)
                for name in root_names(st.target):
                    direct.setdefault(name.split(".")[0], set()).update(srcs)
            elif isinstance(st, (ast.For, ast.AsyncFor)):
                srcs = root_names(st.iter)
                for name in root_names(st.target):
                    direct.setdefault(name.split(".")[0], set()).update(srcs)
            elif isinstance(st, (ast.With, ast.AsyncWith)):
                for item in st.items:
                    if item.optional_vars is not None:
                        srcs = root_names(item.context_expr)
                        for name in root_names(item.optional_vars):
                            direct.setdefault(name.split(".")[0], set()).update(srcs)
            for ch in ast.iter_child_nodes(st):
                if isinstance(ch, ast.stmt):
                    visit_stmts([ch])

    visit_stmts(stmts)

    closure = {}

    def reach(name, seen):
        if name in closure:
            return closure[name]
        if name in seen:
            return {name}
        seen.add(name)
        acc = {name}
        for s in direct.get(name, ()):
            acc |= reach(s.split(".")[0], seen) | {s}
        closure[name] = acc
        return acc

    return {n: reach(n, set()) for n in direct}


# --- guard extraction --------------------------------------------------------


def _test_guards(expr: ast.AST, family: str) -> list:
    """Guard identities inside an if/while/assert test or comprehension if."""
    out = []
    if isinstance(expr, ast.BoolOp):
        for v in expr.values:
            out.extend(_test_guards(v, family))
        return out
    if isinstance(expr, ast.UnaryOp) and isinstance(expr.op, ast.Not):
        return _test_guards(expr.operand, family)
    if isinstance(expr, ast.Compare):
        if expr.ops and isinstance(expr.ops[0], (ast.In, ast.NotIn)):
            right = expr.comparators[0]
            d = dotted_of(right)
            if d and not _const_or_none(right):
                bound = root_names(expr.left) or root_names(right)
                out.append(Guard(f"membership:{d}", frozenset(bound)))
                return out
        if expr.ops and isinstance(expr.ops[0], (ast.Lt, ast.LtE, ast.Gt, ast.GtE)):
            nonconst = [s for s in (expr.left, expr.comparators[0]) if not _const_or_none(s)]
            for side in nonconst:
                if (
                    isinstance(side, ast.Call)
                    and families.basename(dotted_of(side.func) or "") in ("len", "__len__")
                ):
                    out.append(Guard("bounds:len", frozenset(root_names(side))))
                    return out
                d = dotted_of(side) or ""
                if families.SIZE_NAME_RE.search(d):
                    bound = set(root_names(side))
                    for other in nonconst:
                        if other is not side:
                            bound |= root_names(other)
                    out.append(Guard(f"bounds:{d}", frozenset(bound)))
                    return out
            return out
        return out
    if isinstance(expr, ast.Call):
        d = dotted_of(expr.func) or ""
        base = families.basename(d)
        if base == "isinstance" and len(expr.args) >= 2:
            t = dotted_of(expr.args[1]) or "?"
            out.append(Guard(f"type:{t}", frozenset(root_names(expr.args[0]))))
            return out
        if base.startswith(("match", "search", "fullmatch", "findall")) or d.startswith("re."):
            out.append(Guard(f"check:{d}", frozenset(root_names(expr))))
            return out
        if families.is_check_name(d) or (family == "auth-check" and families.is_auth_name(d)):
            cls = "auth" if family == "auth-check" and families.is_auth_name(d) else "check"
            out.append(Guard(f"{cls}:{d}", frozenset(root_names(expr))))
            return out
        return out
    if isinstance(expr, (ast.Name, ast.Attribute)):
        d = dotted_of(expr) or ""
        if family == "auth-check" and families.is_auth_name(d):
            out.append(Guard(f"auth:{d}", frozenset(root_names(expr))))
        return out
    return out


def _is_early_exit(stmt: ast.stmt) -> bool:
    body = getattr(stmt, "body", [])
    if not body:
        return False
    last = body[-1]
    return isinstance(last, (ast.Raise, ast.Return, ast.Continue, ast.Break)) or (
        isinstance(last, ast.Expr)
        and isinstance(last.value, ast.Call)
        and families.basename(dotted_of(last.value.func) or "") in ("exit", "_exit")
    )


def _comprehension_guards(node: ast.AST, produced_names: set, family: str) -> list:
    out = []
    for sub in ast.walk(node):
        if isinstance(sub, ast.comprehension):
            for cond in sub.ifs:
                for g in _test_guards(cond, family):
                    out.append(Guard(g.identity, frozenset(set(g.bound) | produced_names)))
    return out


def _stored_names(st: ast.stmt) -> set:
    out = set()
    for sub in ast.walk(st):
        if isinstance(sub, ast.Assign):
            for t in sub.targets:
                out |= {n.split(".")[0] for n in root_names(t)}
        elif isinstance(sub, (ast.AnnAssign, ast.AugAssign)):
            out |= {n.split(".")[0] for n in root_names(sub.target)}
    return out


def guard_identities_in_frame(frame_node: ast.AST, family: str) -> list:
    """Guard identities in guarding position inside a frame.

    `frame_node` is a FunctionDef/AsyncFunctionDef, or a list of statements
    for module scope. Conditional-branch (non-dominating sibling) bodies
    yield only producing (comprehension/assignment) guards; if/while/assert
    tests, loop/try/with bodies, and auth decorators all count.
    """
    guards = []
    if isinstance(frame_node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        stmts = frame_node.body
        if family == "auth-check":
            for dec in frame_node.decorator_list:
                d = dotted_of(dec.func if isinstance(dec, ast.Call) else dec)
                if d and families.is_auth_name(d):
                    guards.append(Guard(f"auth:{d}", frozenset({"*"})))
    else:
        stmts = list(frame_node)

    def producing_assigns(st):
        for node in ast.walk(st):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None:
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                names = {n.split(".")[0] for t in targets for n in root_names(t)}
                if isinstance(
                    node.value, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)
                ):
                    guards.extend(_comprehension_guards(node.value, names, family))
                elif isinstance(node.value, ast.Call):
                    d = dotted_of(node.value.func) or ""
                    if families.is_sanitizer_name(d) or families.is_check_name(d):
                        guards.append(Guard(f"check:{d}", frozenset(names)))

    def scan(body, conditional: bool):
        for st in body:
            if isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if isinstance(st, ast.If):
                early = _is_early_exit(st)
                # an early-exit check inside a non-dominating branch does not
                # count (KTD4); for a non-early `if`, test names bind only
                # within the if's own suite (scope), while names stored under
                # the test — the filter idiom — bind frame-wide.
                if early:
                    for g in _test_guards(st.test, family):
                        guards.append(Guard(g.identity, frozenset(set(g.bound) | _stored_names(st))))
                elif not conditional:
                    extra = _stored_names(st)
                    for g in _test_guards(st.test, family):
                        if extra:
                            guards.append(Guard(g.identity, frozenset(extra)))
                        guards.append(
                            Guard(g.identity, g.bound, (st.lineno, st.end_lineno))
                        )
                scan(st.body, True)
                scan(st.orelse, conditional)
            elif isinstance(st, (ast.For, ast.AsyncFor, ast.While)):
                if isinstance(st, ast.While) and not conditional:
                    guards.extend(_test_guards(st.test, family))
                scan(st.body, conditional)
                scan(st.orelse, conditional)
            elif isinstance(st, ast.Try):
                scan(st.body, conditional)
                for h in st.handlers:
                    scan(h.body, conditional)
                scan(st.orelse, conditional)
                scan(st.finalbody, conditional)
            elif isinstance(st, (ast.With, ast.AsyncWith)):
                scan(st.body, conditional)
            else:
                if isinstance(st, ast.Assert) and not conditional:
                    guards.extend(_test_guards(st.test, family))
                if isinstance(st, ast.Return) and st.value is not None:
                    # a comprehension filter in the produced value binds the
                    # iterated source name.
                    srcs = set()
                    for sub in ast.walk(st.value):
                        if isinstance(sub, ast.comprehension):
                            srcs |= {n.split(".")[0] for n in root_names(sub.iter)}
                    for g in _comprehension_guards(st.value, srcs, family):
                        guards.append(g)
                if isinstance(st, ast.Expr) and isinstance(st.value, ast.Call) and not conditional:
                    d = dotted_of(st.value.func) or ""
                    if (
                        families.is_check_name(d)
                        or families.is_sanitizer_name(d)
                        or (family == "auth-check" and families.is_auth_name(d))
                    ):
                        guards.append(Guard(f"check:{d}", frozenset(root_names(st.value))))
                producing_assigns(st)

    scan(stmts, False)
    return guards


# --- sink classification -----------------------------------------------------


# Roots that mark an argument as externally influenced even when it is not a
# frame parameter: process env, request headers, inbound data sources.
EXTERNAL_ROOTS = frozenset(
    {"os.environ", "os.getenv", "environ", "request", "headers", "self.env"}
)


def _classify_call(call: ast.Call, importmap: dict) -> Optional[tuple]:
    """(family, group, operation, guarded-arg exprs) or None."""
    func = call.func
    dotted = resolve_dotted(func, importmap) or ""
    base = families.basename(dotted)

    if dotted in families.PARSE_OPS:
        return ("input-validation", f"{dotted}#arg", dotted, [a for a in call.args] + [k.value for k in call.keywords])
    if dotted in families.PATH_OPS:
        return ("input-validation", f"{dotted}#arg0", dotted, list(call.args))
    if dotted in families.SPAWN_ENV_KW_OPS:
        env = next((k.value for k in call.keywords if k.arg == "env"), None)
        if env is not None and not _const_or_none(env):
            return ("input-validation", f"{dotted}#env", dotted, [env])
        return None
    if dotted in families.SPAWN_ENV_TAIL_OPS:
        env = next((k.value for k in call.keywords if k.arg == "env"), None)
        if env is None and len(call.args) > 2:
            # only os.execve/execvpe take env at index 2; spawn*e take it last
            env = call.args[2] if dotted.rsplit(".", 1)[-1].startswith("exec") else call.args[-1]
        if env is not None and not _const_or_none(env):
            return ("input-validation", f"{dotted}#env", dotted, [env])
        return None

    url_vals = [
        k.value for k in call.keywords if k.arg in families.URL_KWARGS and not _const_or_none(k.value)
    ]
    if url_vals:
        roles = ",".join(sorted(k.arg for k in call.keywords if k.arg in families.URL_KWARGS and not _const_or_none(k.value)))
        return ("input-validation", f"{dotted}#{roles}", dotted, url_vals)
    if (
        any(dotted == r or dotted.startswith(r + ".") for r in families.HTTP_ROOTS)
        and base in families.HTTP_VERBS
        and call.args
    ):
        if not _const_or_none(call.args[0]):
            return ("input-validation", f"{dotted}#arg0", dotted, [call.args[0]])

    if base in families.SIZECAP_OPS and isinstance(func, ast.Attribute):
        args = list(call.args)
        # a call carrying its own cap kwarg (read(max_length=n)) is conforming
        cap = next((k.arg for k in call.keywords if k.arg in families.CAP_KWARGS), None)
        if cap is not None:
            return ("size-cap", f"{dotted}#cap:{cap}", dotted, [func.value] + args)
        # bounded literal read/recv (read(4096)) is not an unbounded-input sink
        if args and all(_const_or_none(a) for a in args):
            return None
        return ("size-cap", f"{dotted}#arg", dotted, [func.value] + args)

    return None


# --- per-module analysis -----------------------------------------------------


def _scan_module(info: ModuleInfo) -> list:
    sites = []
    stack = []  # qualname components
    frame_stack = []  # enclosing (func) qualname

    def visit(node):
        nonlocal sites
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            qn = ".".join(stack + [node.name])
            stack.append(node.name)
            if not isinstance(node, ast.ClassDef):
                info.defs[qn] = node
                # auth-check: a handler-decorated def is a privileged site;
                # it conforms when the frame carries an auth guard.
                decs = [
                    dotted_of(d.func if isinstance(d, ast.Call) else d)
                    for d in node.decorator_list
                ]
                handler_dec = next(
                    (d for d in decs if d and families.is_handler_decorator(d)), None
                )
                if handler_dec:
                    params = {a.arg for a in ast.walk(node.args) if isinstance(a, ast.arg)}
                    sites.append(
                        Site(
                            family="auth-check",
                            group=f"handler:{families.basename(handler_dec)}",
                            path=info.relpath,
                            function=qn,
                            line=node.lineno,
                            operation=f"@{handler_dec}",
                            arg_names=frozenset(params | {"*"}),
                            scope=os.path.dirname(info.relpath),
                        )
                    )
            if not isinstance(node, ast.ClassDef):
                frame_stack.append(qn)
            for ch in ast.iter_child_nodes(node):
                visit(ch)
            if not isinstance(node, ast.ClassDef):
                frame_stack.pop()
            stack.pop()
            return
        if isinstance(node, ast.Call):
            cls = _classify_call(node, info.importmap)
            frame = frame_stack[-1] if frame_stack else "<module>"
            if cls:
                fam, group, op, arg_exprs = cls
                s = Site(
                    family=fam,
                    group=group,
                    path=info.relpath,
                    function=frame,
                    line=node.lineno,
                    operation=op,
                    arg_names=frozenset(n for e in arg_exprs for n in root_names(e)),
                    arg_exprs=tuple(arg_exprs),
                    scope=os.path.dirname(info.relpath),
                )
                if "#cap:" in group:
                    s.guard_present = True
                    s.guard_identity = group.split("#cap:", 1)[1]
                sites.append(s)
            info.calls.append((frame, node))
            # args themselves may contain calls; keep walking
        for ch in ast.iter_child_nodes(node):
            visit(ch)

    for st in info.tree.body:
        visit(st)

    # provenance per frame + caller-influenced filter (KTD2): a site counts
    # only when its sink-bound names trace to a frame parameter or an
    # external root (env/request). Module-internal constants do not count.
    kept = []
    per_frame = {}
    for s in sites:
        if s.function not in per_frame:
            info_f = info.defs.get(s.function)
            params = (
                {a.arg for a in ast.walk(info_f.args) if isinstance(a, ast.arg)} - {"self", "cls"}
                if info_f is not None
                else set()
            )
            # closure variables read by a nested def trace to ancestor params
            for i in range(1, s.function.count(".") + 1):
                anc = info.defs.get(s.function.rsplit(".", i)[0])
                if anc is not None:
                    params |= {a.arg for a in ast.walk(anc.args) if isinstance(a, ast.arg)}
            per_frame[s.function] = (
                params,
                frame_provenance(info_f.body) if info_f is not None else {},
            )
        params, prov = per_frame[s.function]
        merged = set(s.arg_names)
        for n in list(s.arg_names):
            merged |= prov.get(n.split(".")[0], set())
        merged |= {f"self.{n}" for n in prov.get("self", set())}
        s.arg_names = frozenset(merged)
        influenced = any(
            n in params or any(n == r or n.startswith(r + ".") for r in EXTERNAL_ROOTS)
            or any((m in params) or any(m == r or m.startswith(r + ".") for r in EXTERNAL_ROOTS)
                   for m in prov.get(n.split(".")[0], set()))
            for n in s.arg_names
        )
        # env-spawn args are ambiently external (os.environ provenance), and
        # auth-check sites are privileged calls whose guard obligation is on
        # the invocation itself, not on caller-influenced args.
        if "#env" in s.group or s.family == "auth-check":
            influenced = True
        if s.function == "<module>" or influenced:
            kept.append(s)
    return kept


def frame_node_of(info: ModuleInfo, function: str):
    """Node whose body is the frame for a site: function def or module stmts."""
    if function == "<module>":
        return info.tree.body
    return info.defs.get(function)


def guards_for_frame(info: ModuleInfo, function: str, family: str) -> list:
    """Memoized guard_identities_in_frame keyed by (function, family)."""
    key = (function, family)
    if key not in info.guard_cache:
        frame = frame_node_of(info, function)
        info.guard_cache[key] = (
            [] if frame is None else guard_identities_in_frame(frame, family)
        )
    return info.guard_cache[key]


def apply_intra_frame_guards(sites: list, modules: dict) -> None:
    for s in sites:
        if s.guard_present:
            continue
        info = modules.get(modpath_for(s.path))
        if info is None:
            continue
        for g in guards_for_frame(info, s.function, s.family):
            if g.scope is not None and not (g.scope[0] <= s.line <= g.scope[1]):
                continue
            if "*" in g.bound or "*" in s.arg_names or \
                    _leaf_names(g.bound) & _leaf_names(s.arg_names):
                s.guard_present = True
                s.guard_identity = g.identity
                break


def scan_repo(root: str) -> ScanResult:
    res = ScanResult([], [], 0, 0, 0)
    state = {"excluded_dirs": 0, "excluded_files": 0, "by_marker": {}}
    for rel, abspath in _walk(root, state):
        try:
            with open(abspath, "r", encoding="utf-8") as fh:
                text = fh.read(MAX_FILE_BYTES + 1)
            if len(text) > MAX_FILE_BYTES:
                raise ValueError("oversized")
            tree = ast.parse(text, filename=rel)
            info = ModuleInfo(rel, modpath_for(rel), tree)
            info.importmap = _import_map(tree)
            res.modules[info.modpath] = info
            res.files_parsed += 1
            res.sites.extend(_scan_module(info))
        except (RecursionError, MemoryError):
            # hostile depth/shape — report and keep walking (KTD7)
            res.parse_errors.append(ParseErrorRec(rel, "RecursionError"))
            continue
        except Exception as e:  # any per-file failure -> parse_error row
            res.parse_errors.append(ParseErrorRec(rel, type(e).__name__))
            continue
    res.excluded_dirs = state["excluded_dirs"]
    res.excluded_files = state["excluded_files"]
    res.by_marker = state["by_marker"]
    try:
        apply_intra_frame_guards(res.sites, res.modules)
    except RecursionError:
        pass  # deep guard walk degrades to unguarded sites, not a crash
    return res
