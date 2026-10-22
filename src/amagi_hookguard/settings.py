"""Find Claude Code settings files and add or remove the hookguard wiring."""

from __future__ import annotations

import json
import os
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .config import claude_home

MARKERS = ("amagi-hookguard", "amagi_hookguard")
DEFAULT_COMMAND = "amagi-hookguard hook"
HOOK_TIMEOUT = 10
WIRED_EVENTS = ("PreToolUse", "PostToolUse")


@dataclass
class SettingsFile:
    scope: str
    path: Path


def managed_settings_path() -> Path:
    if sys.platform.startswith("win"):
        return Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "ClaudeCode" / "managed-settings.json"
    if sys.platform == "darwin":
        return Path("/Library/Application Support/ClaudeCode/managed-settings.json")
    return Path("/etc/claude-code/managed-settings.json")


def settings_files(project_dir: Optional[str]) -> List[SettingsFile]:
    files = [SettingsFile("user", claude_home() / "settings.json")]
    if project_dir:
        base = Path(project_dir) / ".claude"
        files.append(SettingsFile("project", base / "settings.json"))
        files.append(SettingsFile("local", base / "settings.local.json"))
    files.append(SettingsFile("managed", managed_settings_path()))
    return files


def scope_path(scope: str, project_dir: Optional[str]) -> Path:
    for f in settings_files(project_dir or os.getcwd()):
        if f.scope == scope:
            return f.path
    raise ValueError(f"unknown scope {scope!r}")


def is_hookguard_command(command: Any) -> bool:
    return isinstance(command, str) and any(m in command for m in MARKERS)


def hook_command(absolute: bool = False) -> str:
    if not absolute:
        return DEFAULT_COMMAND
    exe = shutil.which("amagi-hookguard")
    if exe:
        return f'"{Path(exe).as_posix()}" hook'
    return f'"{Path(sys.executable).as_posix()}" -m amagi_hookguard hook'


def load(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {}
    text = path.read_text(encoding="utf-8-sig")
    if not text.strip():
        return {}
    data = json.loads(text)
    if not isinstance(data, dict):
        raise ValueError(f"{path}: top level must be a JSON object")
    return data


def strip_hookguard(data: Dict[str, Any]) -> int:
    """Remove every hookguard command from data['hooks']; return how many were removed."""
    hooks = data.get("hooks")
    if not isinstance(hooks, dict):
        return 0
    removed = 0
    for event in list(hooks.keys()):
        groups = hooks[event]
        if not isinstance(groups, list):
            continue
        kept_groups = []
        for group in groups:
            if not isinstance(group, dict) or not isinstance(group.get("hooks"), list):
                kept_groups.append(group)
                continue
            inner = [h for h in group["hooks"] if not (isinstance(h, dict) and is_hookguard_command(h.get("command")))]
            removed += len(group["hooks"]) - len(inner)
            if inner:
                group = dict(group)
                group["hooks"] = inner
                kept_groups.append(group)
        if kept_groups:
            hooks[event] = kept_groups
        else:
            del hooks[event]
    if not hooks:
        del data["hooks"]
    return removed


def add_hookguard(data: Dict[str, Any], command: str) -> None:
    hooks = data.setdefault("hooks", {})
    if not isinstance(hooks, dict):
        raise ValueError("'hooks' in settings is not an object; fix it by hand first")
    for event in WIRED_EVENTS:
        groups = hooks.setdefault(event, [])
        if not isinstance(groups, list):
            raise ValueError(f"'hooks.{event}' in settings is not a list; fix it by hand first")
        groups.append({"matcher": "*", "hooks": [{"type": "command", "command": command, "timeout": HOOK_TIMEOUT}]})


def install(path: Path, command: str, dry_run: bool = False) -> Tuple[str, Optional[Path]]:
    """Wire hookguard into `path`. Returns (new JSON text, backup path or None)."""
    data = load(path)
    strip_hookguard(data)
    add_hookguard(data, command)
    text = json.dumps(data, indent=2, ensure_ascii=False) + "\n"
    backup = None
    if not dry_run:
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists():
            backup = path.with_name(path.name + ".bak-hookguard")
            shutil.copy2(path, backup)
        path.write_text(text, encoding="utf-8")
    return text, backup


def uninstall(path: Path, dry_run: bool = False) -> Tuple[int, Optional[Path]]:
    data = load(path)
    removed = strip_hookguard(data)
    backup = None
    if removed and not dry_run:
        backup = path.with_name(path.name + ".bak-hookguard")
        shutil.copy2(path, backup)
        path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return removed, backup
