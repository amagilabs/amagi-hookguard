"""The hook entry point Claude Code runs: reads one event as JSON on stdin.

PreToolUse:  block -> exit 2, reason on stderr (Claude Code shows it to the model).
             ask   -> exit 0, JSON permissionDecision "ask" on stdout.
             allow -> exit 0, no output.
PostToolUse (and anything else): append one audit line, exit 0.
"""

from __future__ import annotations

import json
import os
import sys
from typing import Any, Dict, Optional, TextIO

from . import audit
from .config import Config, load_config
from .rules import ASK, BLOCK, Decision, evaluate

EXIT_OK = 0
EXIT_ERROR = 1  # non-blocking error: Claude Code shows stderr to the user and carries on
EXIT_BLOCK = 2


def _project_dir(event: Dict[str, Any]) -> Optional[str]:
    return os.environ.get("CLAUDE_PROJECT_DIR") or event.get("cwd")


def _base_record(event: Dict[str, Any], name: str) -> Dict[str, Any]:
    return {
        "ts": audit.now_iso(),
        "event": name,
        "session": event.get("session_id"),
        "cwd": event.get("cwd"),
        "tool": event.get("tool_name"),
        "input": audit.summarize_input(event.get("tool_name") or "", event.get("tool_input")),
    }


def _safe_write(record: Dict[str, Any], cfg: Config, stderr: TextIO) -> None:
    try:
        audit.write(record, cfg)
    except OSError as exc:
        stderr.write(f"amagi-hookguard: could not write audit log: {exc}\n")


def handle_pre(event: Dict[str, Any], cfg: Config, stdout: TextIO, stderr: TextIO) -> int:
    decision: Decision = evaluate(event.get("tool_name") or "", event.get("tool_input"), event.get("cwd"), cfg)
    if decision.action == "allow":
        return EXIT_OK
    record = _base_record(event, "PreToolUse")
    record.update({"decision": decision.action, "rule": decision.rule, "reason": decision.reason})
    _safe_write(record, cfg, stderr)
    message = (
        f"amagi-hookguard {'blocked' if decision.action == BLOCK else 'flagged'} this "
        f"{event.get('tool_name')} call [{decision.rule}]: {decision.reason}."
    )
    if decision.action == BLOCK:
        stderr.write(
            message
            + " If the user really wants this, they can run it themselves or disable the rule in hookguard.json.\n"
        )
        return EXIT_BLOCK
    if decision.action == ASK:
        out = {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "ask",
                "permissionDecisionReason": message,
            }
        }
        stdout.write(json.dumps(out) + "\n")
    return EXIT_OK


def handle_other(event: Dict[str, Any], name: str, cfg: Config, stderr: TextIO) -> int:
    record = _base_record(event, name)
    if "tool_response" in event:
        response = event.get("tool_response")
        record["ok"] = audit.response_ok(response)
        record["response_chars"] = audit.response_size(response)
    elif name == "PostToolUseFailure":
        record["ok"] = False
    _safe_write(record, cfg, stderr)
    return EXIT_OK


def run(stdin: TextIO = None, stdout: TextIO = None, stderr: TextIO = None) -> int:
    stdout = stdout or sys.stdout
    stderr = stderr or sys.stderr
    if stdin is None:
        # Claude Code sends UTF-8; don't let a Windows console code page garble paths.
        raw = sys.stdin.buffer.read().decode("utf-8", "replace")
    else:
        raw = stdin.read()
    try:
        event = json.loads(raw)
        if not isinstance(event, dict):
            raise ValueError("event is not a JSON object")
    except ValueError as exc:
        stderr.write(f"amagi-hookguard: could not parse hook input: {exc}\n")
        return EXIT_ERROR
    cfg = load_config(_project_dir(event))
    name = event.get("hook_event_name") or ""
    try:
        if name == "PreToolUse":
            return handle_pre(event, cfg, stdout, stderr)
        return handle_other(event, name or "unknown", cfg, stderr)
    except Exception as exc:  # the guard itself failed
        stderr.write(f"amagi-hookguard: internal error: {exc!r}\n")
        if name == "PreToolUse" and cfg.fail_closed:
            stderr.write("amagi-hookguard: fail_closed is on, so the call is blocked.\n")
            return EXIT_BLOCK
        return EXIT_ERROR
