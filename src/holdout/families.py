"""Family tables: sink operations, guard-shape vocabulary, normalization.

Hand-maintained against SPEC.md's family table. Canonical order follows the
spec table; only the v1 families are implemented.
"""

from __future__ import annotations

import re

# v1 families in SPEC.md table order.
FAMILIES = ("size-cap", "input-validation", "auth-check")

# --- sink ops ---------------------------------------------------------------

# input-validation: deserializers evaluated as literal-parse sinks.
PARSE_OPS = frozenset({"json.loads", "yaml.load", "ast.literal_eval"})

# input-validation: filesystem path sinks.
PATH_OPS = frozenset({"open", "os.path.join", "io.open"})

# input-validation: process-spawn ops where an env channel (keyword or
# positional) is the guarded argument.
SPAWN_ENV_KW_OPS = frozenset(
    {
        "subprocess.run",
        "subprocess.Popen",
        "subprocess.call",
        "subprocess.check_call",
        "subprocess.check_output",
    }
)
# os.exec*e / os.spawn*e take env as the last positional arg (execle/execlpe)
# or index 2 (execve/execvpe/execvpe-style); handled in the matcher.
SPAWN_ENV_TAIL_OPS = frozenset(
    {
        "os.execve",
        "os.execvpe",
        "os.execle",
        "os.execlpe",
        "os.spawnve",
        "os.spawnvpe",
        "os.spawnlve",
    }
)

# input-validation: URL-bearing construction/consumption (SSRF class).
URL_KWARGS = frozenset({"url", "base_url", "endpoint", "server_url", "uri"})
HTTP_ROOTS = frozenset({"requests", "httpx", "aiohttp", "urllib.request", "urllib3"})
HTTP_VERBS = frozenset(
    {"get", "post", "put", "delete", "patch", "head", "options", "request", "urlopen", "urlretrieve"}
)

# size-cap: reads/decodes/decompresses of unbounded input.
SIZECAP_OPS = frozenset({"read", "readall", "recv", "recvfrom", "decompress", "decode"})

# size-cap: keyword caps on the sink call itself make it a conforming site.
CAP_KWARGS = frozenset(
    {"max_length", "maxlen", "max_size", "max_bytes", "budget", "limit", "limit_bytes"}
)

# auth-check: decorators marking a handler whose body needs an authz guard.
HANDLER_DEC_RE = re.compile(
    r"(?i)(route|tool|handler|rpc|endpoint|command|register|get|post|put|delete|patch|head|options)"
)


def is_handler_decorator(dotted: str) -> bool:
    base = basename(dotted)
    return bool(HANDLER_DEC_RE.search(base)) and not is_auth_name(dotted)

# --- guard shapes -----------------------------------------------------------

# Call-name prefixes that mark a check/sanitizer helper in any family.
CHECK_PREFIXES = (
    "check_",
    "validate_",
    "verify_",
    "ensure_",
    "is_",
    "has_",
    "allow",
    "require_",
    "assert_",
)

# Sanitizer prefixes: assignment `x = f(...)` where f matches is a produced
# guard on x even before callee resolution.
SANITIZER_PREFIXES = ("sanitize_", "sanitise_", "scrub_", "filter_", "clean_")

# auth-check family: names (test or bare statement) carrying an auth guard.
AUTH_RE = re.compile(
    r"(?i)(auth|login|permission|permit|authoriz|is_admin|allowed"
    r"|capabilit|forbidden|access_|_check_)"
)

# Names that read like a size/length operand in a bounds compare.
SIZE_NAME_RE = re.compile(r"(?i)(len|size|length|count|bytes|num_|total)")


def basename(dotted: str) -> str:
    return dotted.rsplit(".", 1)[-1]


def is_check_name(name: str) -> bool:
    base = basename(name).lstrip("_")
    return base.startswith(CHECK_PREFIXES)


def is_sanitizer_name(name: str) -> bool:
    base = basename(name).lstrip("_")
    return base.startswith(SANITIZER_PREFIXES)


def is_auth_name(name: str) -> bool:
    return bool(AUTH_RE.search(basename(name)))
