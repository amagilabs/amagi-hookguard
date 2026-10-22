import os
import shutil
import subprocess
import sys

import pytest

from amagi_hookguard.config import Config


@pytest.fixture(autouse=True)
def isolated_home(tmp_path, monkeypatch):
    """Keep every test away from the real ~/.claude and the real audit log."""
    home = tmp_path / "claude-home"
    home.mkdir()
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(home))
    monkeypatch.setenv("AMAGI_HOOKGUARD_AUDIT", str(tmp_path / "audit.jsonl"))
    monkeypatch.delenv("CLAUDE_PROJECT_DIR", raising=False)
    return home


@pytest.fixture
def cfg():
    return Config()


@pytest.fixture
def audit_file(tmp_path):
    return tmp_path / "audit.jsonl"


def _git(*args, cwd):
    return subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True)


@pytest.fixture
def git_repo(tmp_path):
    """A fresh repo with HEAD on `main`."""
    if shutil.which("git") is None:
        pytest.skip("git not installed")
    repo = tmp_path / "repo"
    repo.mkdir()
    _git("init", "-q", cwd=repo)
    _git("symbolic-ref", "HEAD", "refs/heads/main", cwd=repo)

    return GitRepo(repo)


class GitRepo:
    def __init__(self, path):
        self.path = path

    def __str__(self):
        return str(self.path)

    def checkout(self, branch):
        _git("symbolic-ref", "HEAD", f"refs/heads/{branch}", cwd=self.path)


HOOK_CMD = [sys.executable, "-m", "amagi_hookguard"]
