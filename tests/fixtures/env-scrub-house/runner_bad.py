import os
import subprocess


def run_experiment(cmd):
    # raw env pass-through: no scrub against _SAFE_ENV_BLOCKLIST
    env = os.environ.copy()
    env["EXPERIMENT"] = "1"
    subprocess.run(cmd, env=env)
