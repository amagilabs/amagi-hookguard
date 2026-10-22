"""Load hookguard.json from the user and project .claude folders.

The user file can do anything. A project file (checked into a repo you may
not control) can only add protection unless the user file sets
"trust_project_config": true.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Dict, List, Optional

CONFIG_NAME = "hookguard.json"
DEFAULT_PROTECTED = ["main", "master"]

KNOWN_KEYS = {
    "disabled_rules",
    "protected_branches",
    "secret_globs",
    "secret_allow_globs",
    "allow_commands",
    "ask_as_block",
    "fail_closed",
    "audit_log",
    "audit_max_bytes",
    "trust_project_config",
}
# Keys an untrusted project file may set: they only make the guard stricter.
STRICTER_KEYS = {"protected_branches", "secret_globs", "ask_as_block", "fail_closed"}


class Config:
    # A plain class rather than a dataclass: importing dataclasses pulls in
    # inspect and ast, which roughly doubles the hook's start-up time.
    def __init__(self) -> None:
        self.disabled_rules: List[str] = []
        self.protected_branches: List[str] = list(DEFAULT_PROTECTED)
        self.secret_globs: List[str] = []
        self.secret_allow_globs: List[str] = []
        self.allow_commands: List[str] = []
        self.ask_as_block = False
        self.fail_closed = False
        self.audit_log: Optional[str] = None
        self.audit_max_bytes = 10_000_000
        self.sources: List[str] = []
        self.notes: List[str] = []

    def __repr__(self) -> str:
        return f"Config({self.__dict__!r})"


def claude_home() -> Path:
    env = os.environ.get("CLAUDE_CONFIG_DIR")
    return Path(env).expanduser() if env else Path.home() / ".claude"


def user_config_path() -> Path:
    return claude_home() / CONFIG_NAME


def project_config_path(project_dir: Optional[str]) -> Optional[Path]:
    if not project_dir:
        return None
    return Path(project_dir) / ".claude" / CONFIG_NAME


def read_json(path: Path) -> Dict:
    with open(path, "r", encoding="utf-8-sig") as fh:
        data = json.load(fh)
    if not isinstance(data, dict):
        raise ValueError("top level must be a JSON object")
    return data


def _apply(cfg: Config, data: Dict, path: Path, trusted: bool) -> None:
    for key, value in data.items():
        if key not in KNOWN_KEYS:
            cfg.notes.append(f"{path}: unknown key '{key}' ignored")
            continue
        if not trusted and key not in STRICTER_KEYS:
            cfg.notes.append(
                f"{path}: '{key}' ignored (project config can only add protection; "
                "set \"trust_project_config\": true in your user hookguard.json to allow it)"
            )
            continue
        if key in ("ask_as_block", "fail_closed"):
            if not trusted:
                if value is True:
                    setattr(cfg, key, True)
            else:
                setattr(cfg, key, bool(value))
        elif key in ("audit_max_bytes",):
            try:
                cfg.audit_max_bytes = int(value)
            except (TypeError, ValueError):
                cfg.notes.append(f"{path}: audit_max_bytes must be a number")
        elif key in ("audit_log",):
            cfg.audit_log = str(value) if value else None
        elif key == "trust_project_config":
            pass
        else:
            if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
                cfg.notes.append(f"{path}: '{key}' must be a list of strings")
                continue
            current = getattr(cfg, key)
            for v in value:
                if v not in current:
                    current.append(v)


def load_config(project_dir: Optional[str] = None) -> Config:
    cfg = Config()
    trust_project = False
    upath = user_config_path()
    if upath.is_file():
        try:
            data = read_json(upath)
            _apply(cfg, data, upath, trusted=True)
            trust_project = data.get("trust_project_config") is True
            cfg.sources.append(str(upath))
        except (OSError, ValueError) as exc:
            cfg.notes.append(f"{upath}: could not read ({exc})")
    ppath = project_config_path(project_dir)
    if ppath is not None and ppath.is_file() and ppath.resolve() != upath.resolve():
        try:
            _apply(cfg, read_json(ppath), ppath, trusted=trust_project)
            cfg.sources.append(str(ppath))
        except (OSError, ValueError) as exc:
            cfg.notes.append(f"{ppath}: could not read ({exc})")
    return cfg
