import os

_SAFE_ENV_BLOCKLIST = {"LD_PRELOAD", "LD_LIBRARY_PATH", "PYTHONPATH"}


def _scrub_env(env):
    return {k: v for k, v in env.items() if k not in _SAFE_ENV_BLOCKLIST}
