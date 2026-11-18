import os
import subprocess

from helpers import _scrub_env


def run_fmt(env):
    subprocess.run(["fmt"], env=_scrub_env(env))


def run_lint(env):
    subprocess.run(["lint"], env=_scrub_env(env))


def run_tests():
    subprocess.run(["pytest"], env=_scrub_env(os.environ))


def run_build():
    env = _scrub_env(os.environ)
    subprocess.run(["make"], env=env)


def run_docs(env):
    subprocess.run(["mkdocs"], env=_scrub_env(env))


def run_deploy(env):
    subprocess.run(["deploy"], env=_scrub_env(env))
