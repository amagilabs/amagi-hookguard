"""`amagi-hookguard doctor`: check how hooks are wired in Claude Code settings files."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import __version__, audit
from .config import load_config
from .settings import SettingsFile, is_hookguard_command, settings_files
from .shell import command_name, tokenize

OK, INFO, WARN, FAIL = "ok", "info", "WARN", "FAIL"

KNOWN_EVENTS = [
    "PreToolUse", "PostToolUse", "PostToolUseFailure", "PermissionRequest", "Notification",
    "UserPromptSubmit", "Stop", "SubagentStart", "SubagentStop", "PreCompact", "SessionStart", "SessionEnd",
]
KNOWN_TOOLS = [
    "Bash", "PowerShell", "Read", "Write", "Edit", "MultiEdit", "Grep", "Glob", "LS", "WebFetch",
    "WebSearch", "Task", "Agent", "NotebookEdit", "NotebookRead", "TodoWrite", "Skill", "BashOutput",
    "KillShell", "ExitPlanMode", "SlashCommand",
]
INTERPRETERS = {"python", "python3", "py", "node", "bash", "sh", "zsh", "pwsh", "powershell", "deno", "bun", "ruby", "perl", "uv"}
SCRIPT_EXT = (".py", ".js", ".mjs", ".cjs", ".ts", ".sh", ".ps1", ".rb", ".pl")


@dataclass
class Finding:
    level: str
    code: str
    message: str


@dataclass
class Section:
    title: str
    findings: List[Finding] = field(default_factory=list)

    def add(self, level: str, code: str, message: str) -> None:
        self.findings.append(Finding(level, code, message))


@dataclass
class Wiring:
    scope: str
    path: Path
    event: str
    matcher: Optional[str]
    command: str
    timeout: Any


def display_path(path: Any) -> str:
    text = str(path)
    home = str(Path.home())
    if text.lower().startswith(home.lower()):
        text = "~" + text[len(home):]
    return text.replace("\\", "/")


def required_tools() -> List[str]:
    tools = ["Bash", "Read", "Grep"]
    if sys.platform.startswith("win"):
        tools.append("PowerShell")
    return tools


def matcher_covers(matcher: Optional[str], tool: str) -> bool:
    if matcher is None or matcher in ("", "*"):
        return True
    try:
        if re.fullmatch(matcher, tool):
            return True
    except re.error:
        pass
    return matcher == tool


def matcher_covers_all(matcher: Optional[str]) -> bool:
    return matcher is None or matcher in ("", "*", ".*", ".+")


def expand_command(command: str, project_dir: str) -> str:
    out = command
    for token in ("${CLAUDE_PROJECT_DIR}", "$CLAUDE_PROJECT_DIR", "%CLAUDE_PROJECT_DIR%"):
        out = out.replace(token, project_dir)
    return os.path.expandvars(out)


def command_problems(command: str, project_dir: str) -> List[str]:
    """Why `command` would fail to start, as far as we can tell without running it."""
    expanded = expand_command(command, project_dir)
    tokens = [t for t in tokenize(expanded) if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", t)]
    if not tokens:
        return ["command is empty"]
    exe = os.path.expanduser(tokens[0])
    problems: List[str] = []
    if "/" in exe or "\\" in exe:
        p = Path(exe)
        if not p.is_absolute():
            p = Path(project_dir) / p
        if not (p.exists() or Path(str(p) + ".exe").exists()):
            problems.append(f"executable not found: {display_path(exe)}")
    elif shutil.which(exe) is None:
        problems.append(f"'{exe}' is not on PATH")
    if command_name(exe) in INTERPRETERS:
        args = tokens[1:]
        for i, a in enumerate(args):
            if a in ("-m", "-c", "-e", "-Command", "-c", "run", "-x"):
                break
            if a.startswith("-"):
                continue
            if a.lower().endswith(SCRIPT_EXT):
                sp = Path(os.path.expanduser(a))
                if not sp.is_absolute():
                    sp = Path(project_dir) / sp
                if not sp.exists():
                    problems.append(f"script not found: {display_path(a)}")
            break
    return problems


def check_file(sf: SettingsFile, project_dir: str, wiring: List[Wiring]) -> Section:
    sec = Section(f"{sf.scope:<8} {display_path(sf.path)}")
    try:
        text = sf.path.read_text(encoding="utf-8-sig")
    except OSError as exc:
        sec.add(FAIL, "unreadable", f"cannot read file: {exc}")
        return sec
    if not text.strip():
        sec.add(INFO, "empty", "file is empty")
        return sec
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        sec.add(FAIL, "json-invalid", f"not valid JSON (line {exc.lineno}, column {exc.colno}: {exc.msg}); Claude Code will ignore this file")
        return sec
    if not isinstance(data, dict):
        sec.add(FAIL, "json-invalid", "top level is not a JSON object")
        return sec
    sec.add(OK, "json", "valid JSON")
    if data.get("disableAllHooks") is True:
        sec.add(FAIL, "hooks-disabled", '"disableAllHooks": true turns every hook off, including hookguard')
    perms = data.get("permissions")
    if isinstance(perms, dict) and perms.get("defaultMode") == "bypassPermissions":
        sec.add(INFO, "bypass-mode", "defaultMode is bypassPermissions: hooks are the only thing between the model and your shell")
    hooks = data.get("hooks")
    if hooks is None:
        sec.add(INFO, "no-hooks", "no hooks configured here")
        return sec
    if not isinstance(hooks, dict):
        sec.add(FAIL, "hooks-shape", '"hooks" must be an object keyed by event name')
        return sec
    lower_events = {e.lower(): e for e in KNOWN_EVENTS}
    lower_tools = {t.lower(): t for t in KNOWN_TOOLS}
    count = 0
    for event, groups in hooks.items():
        if event not in KNOWN_EVENTS:
            if event.lower() in lower_events:
                sec.add(FAIL, "event-case", f"event '{event}' should be '{lower_events[event.lower()]}' (case-sensitive; this block never runs)")
            else:
                sec.add(WARN, "event-unknown", f"'{event}' is not a hook event amagi-hookguard knows; check the spelling")
        if not isinstance(groups, list):
            sec.add(FAIL, "hooks-shape", f"hooks.{event} must be a list of matcher groups")
            continue
        for gi, group in enumerate(groups):
            where = f"hooks.{event}[{gi}]"
            if not isinstance(group, dict) or not isinstance(group.get("hooks"), list):
                sec.add(FAIL, "hooks-shape", f'{where} needs a "hooks" list (shape: {{"matcher": "...", "hooks": [{{"type": "command", "command": "..."}}]}})')
                continue
            matcher = group.get("matcher")
            if matcher is not None and not isinstance(matcher, str):
                sec.add(FAIL, "matcher-type", f"{where}.matcher must be a string")
                matcher = None
            if isinstance(matcher, str) and matcher not in ("", "*"):
                try:
                    re.compile(matcher)
                except re.error as exc:
                    sec.add(FAIL, "matcher-regex", f"{where}.matcher {matcher!r} is not a valid regex ({exc})")
                for part in matcher.split("|"):
                    if part in lower_tools and part != lower_tools[part]:
                        sec.add(FAIL, "matcher-case", f"{where}.matcher {matcher!r}: '{part}' never matches '{lower_tools[part]}' (case-sensitive)")
            for hi, hook in enumerate(group["hooks"]):
                hwhere = f"{where}.hooks[{hi}]"
                if not isinstance(hook, dict):
                    sec.add(FAIL, "hooks-shape", f"{hwhere} must be an object")
                    continue
                htype = hook.get("type")
                if htype is None:
                    sec.add(FAIL, "hook-type", f'{hwhere} has no "type" (use "command")')
                    continue
                if htype != "command":
                    sec.add(INFO, "hook-type", f'{hwhere} has type {htype!r}; only "command" hooks are checked')
                    continue
                command = hook.get("command")
                if not isinstance(command, str) or not command.strip():
                    sec.add(FAIL, "command-empty", f'{hwhere} has no "command"')
                    continue
                count += 1
                timeout = hook.get("timeout")
                if timeout is not None and (isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or timeout <= 0):
                    sec.add(FAIL, "timeout", f"{hwhere}.timeout must be a positive number of seconds, got {timeout!r}")
                for problem in command_problems(command, project_dir):
                    sec.add(FAIL, "command-not-found", f"{event} hook `{command}`: {problem}")
                if is_hookguard_command(command):
                    wiring.append(Wiring(sf.scope, sf.path, event, matcher, command, timeout))
    sec.add(OK if count else INFO, "hook-count", f"{count} command hook(s) found")
    return sec


def check_wiring(wiring: List[Wiring]) -> Section:
    sec = Section("hookguard wiring")
    pre = [w for w in wiring if w.event == "PreToolUse"]
    post = [w for w in wiring if w.event == "PostToolUse"]
    if not pre:
        sec.add(FAIL, "pre-missing", "no PreToolUse hook runs amagi-hookguard, so nothing is blocked. Fix: amagi-hookguard install")
    else:
        missing = [t for t in required_tools() if not any(matcher_covers(w.matcher, t) for w in pre)]
        if missing:
            sec.add(FAIL, "pre-coverage", f"PreToolUse matcher(s) {[w.matcher for w in pre]} skip {', '.join(missing)}; use \"*\"")
        else:
            w = pre[0]
            sec.add(OK, "pre", f"PreToolUse runs hookguard for {', '.join(required_tools())} ({w.scope}, matcher {w.matcher!r})")
    if not post:
        sec.add(WARN, "post-missing", "no PostToolUse hook runs amagi-hookguard, so nothing is logged. Fix: amagi-hookguard install")
    elif not any(matcher_covers_all(w.matcher) for w in post):
        sec.add(WARN, "post-coverage", f"PostToolUse matcher(s) {[w.matcher for w in post]} log only some tools; use \"*\" to log every call")
    else:
        w = next(w for w in post if matcher_covers_all(w.matcher))
        sec.add(OK, "post", f"PostToolUse logs every tool call ({w.scope}, matcher {w.matcher!r})")
    for event, entries in (("PreToolUse", pre), ("PostToolUse", post)):
        if len(entries) > 1:
            where = ", ".join(f"{w.scope}" for w in entries)
            sec.add(WARN, "duplicate", f"hookguard is wired {len(entries)} times for {event} ({where}); every call runs it {len(entries)} times")
    return sec


def _run_hook(command: str, event: Dict[str, Any], env: Dict[str, str], cwd: str, timeout: float):
    return subprocess.run(
        command,
        shell=True,
        input=json.dumps(event),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=env,
        cwd=cwd,
        timeout=timeout,
    )


def self_test(wiring: List[Wiring], project_dir: str) -> Section:
    sec = Section("self-test (runs the wired command with sample events; nothing is executed)")
    pre = next((w for w in wiring if w.event == "PreToolUse"), None)
    post = next((w for w in wiring if w.event == "PostToolUse"), None)
    if pre is None and post is None:
        sec.add(INFO, "selftest-skipped", "skipped: hookguard is not wired")
        return sec
    with tempfile.TemporaryDirectory(prefix="hookguard-doctor-") as tmp:
        log = Path(tmp) / "audit.jsonl"
        env = dict(os.environ)
        env[audit.ENV_VAR] = str(log)
        env.setdefault("CLAUDE_PROJECT_DIR", project_dir)
        base = {"session_id": "doctor-self-test", "cwd": tmp, "transcript_path": ""}
        cases = []
        if pre is not None:
            cases = [
                ("Bash `rm -rf ~`", {"tool_name": "Bash", "tool_input": {"command": "rm -rf ~"}}, 2),
                ("Read `.env`", {"tool_name": "Read", "tool_input": {"file_path": os.path.join(tmp, ".env")}}, 2),
                ("Bash `git push --force origin main`", {"tool_name": "Bash", "tool_input": {"command": "git push --force origin main"}}, 2),
                ("Bash `ls -la`", {"tool_name": "Bash", "tool_input": {"command": "ls -la"}}, 0),
            ]
            for label, extra, want in cases:
                event = dict(base, hook_event_name="PreToolUse", **extra)
                command = expand_command(pre.command, project_dir)
                try:
                    res = _run_hook(command, event, env, tmp, float(pre.timeout or 10) + 5)
                except subprocess.TimeoutExpired:
                    sec.add(FAIL, "selftest-timeout", f"{label}: hook did not answer within {pre.timeout or 10}s")
                    continue
                verdict = "blocked" if res.returncode == 2 else ("allowed" if res.returncode == 0 else f"exit {res.returncode}")
                if res.returncode == want:
                    sec.add(OK, "selftest", f"{label} -> {verdict} (exit {res.returncode})")
                else:
                    detail = (res.stderr or res.stdout).strip().splitlines()
                    tail = f": {detail[-1]}" if detail else ""
                    sec.add(FAIL, "selftest", f"{label} -> {verdict}, expected exit {want}{tail}")
        if post is not None:
            event = dict(base, hook_event_name="PostToolUse", tool_name="Bash",
                         tool_input={"command": "echo doctor"}, tool_response={"stdout": "doctor", "stderr": "", "interrupted": False})
            try:
                res = _run_hook(expand_command(post.command, project_dir), event, env, tmp, float(post.timeout or 10) + 5)
                lines = list(audit.read(log))
                if res.returncode == 0 and any(r.get("event") == "PostToolUse" for r in lines):
                    sec.add(OK, "selftest", "PostToolUse event -> written to the audit log")
                else:
                    sec.add(FAIL, "selftest", f"PostToolUse event -> exit {res.returncode}, no audit line written")
            except subprocess.TimeoutExpired:
                sec.add(FAIL, "selftest-timeout", "PostToolUse hook did not answer in time")
    return sec


def check_audit_and_config(project_dir: str) -> Section:
    cfg = load_config(project_dir)
    sec = Section("config and audit log")
    for src in cfg.sources:
        sec.add(OK, "config", f"loaded {display_path(src)}")
    if not cfg.sources and not cfg.notes:
        sec.add(INFO, "config", "no hookguard.json found; using defaults (protected branches: main, master)")
    for note in cfg.notes:
        sec.add(WARN, "config", display_path(note) if note.startswith(str(Path.home())) else note)
    path = audit.audit_path(cfg)
    probe = path.parent
    while not probe.exists() and probe.parent != probe:
        probe = probe.parent
    if not os.access(probe, os.W_OK):
        sec.add(FAIL, "audit-unwritable", f"cannot write audit log under {display_path(probe)}")
    elif path.exists():
        records = list(audit.read(path))
        blocked = sum(1 for r in records if r.get("decision") == "block")
        last = records[-1].get("ts") if records else "never"
        sec.add(OK, "audit", f"{display_path(path)}: {len(records)} entries, {blocked} blocked, last {last}")
    else:
        sec.add(INFO, "audit", f"{display_path(path)} does not exist yet (created on the first logged call)")
    return sec


def run_doctor(project_dir: Optional[str] = None, files: Optional[List[str]] = None, execute: bool = True) -> List[Section]:
    project_dir = os.path.abspath(project_dir or os.getcwd())
    sections: List[Section] = []
    wiring: List[Wiring] = []
    if files:
        targets = [SettingsFile("file", Path(f)) for f in files]
    else:
        targets = settings_files(project_dir)
    for sf in targets:
        if not sf.path.exists():
            if sf.scope != "managed":
                sec = Section(f"{sf.scope:<8} {display_path(sf.path)}")
                sec.add(FAIL if sf.scope == "file" else INFO, "missing", "file not found")
                sections.append(sec)
            continue
        sections.append(check_file(sf, project_dir, wiring))
    sections.append(check_wiring(wiring))
    if execute:
        sections.append(self_test(wiring, project_dir))
    sections.append(check_audit_and_config(project_dir))
    return sections


def counts(sections: List[Section]) -> Dict[str, int]:
    c = {FAIL: 0, WARN: 0}
    for s in sections:
        for f in s.findings:
            if f.level in c:
                c[f.level] += 1
    return c


def render(sections: List[Section]) -> str:
    lines = [f"amagi-hookguard doctor {__version__}", ""]
    for s in sections:
        lines.append(s.title)
        for f in s.findings:
            lines.append(f"  {f.level:<4}  {f.message}")
        lines.append("")
    c = counts(sections)
    verdict = "FAIL" if c[FAIL] else "PASS"
    lines.append(f"Result: {verdict} ({c[FAIL]} fail, {c[WARN]} warn)")
    return "\n".join(lines)


def to_json(sections: List[Section]) -> str:
    c = counts(sections)
    return json.dumps(
        {
            "version": __version__,
            "result": "FAIL" if c[FAIL] else "PASS",
            "fail": c[FAIL],
            "warn": c[WARN],
            "sections": [
                {"title": s.title, "findings": [f.__dict__ for f in s.findings]} for s in sections
            ],
        },
        indent=2,
    )
