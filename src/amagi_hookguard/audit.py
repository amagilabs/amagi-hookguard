"""Append-only JSONL audit log of tool calls, with secrets redacted."""

from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

from .config import Config, claude_home

ENV_VAR = "AMAGI_HOOKGUARD_AUDIT"
MAX_FIELD = 400

_REDACTIONS = [
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(-----END [A-Z ]*PRIVATE KEY-----|$)", re.S), "[REDACTED PRIVATE KEY]"),
    (re.compile(r"\b(sk|rk|pk)-[A-Za-z0-9_-]{16,}"), "[REDACTED]"),
    (re.compile(r"\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}"), "[REDACTED]"),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}"), "[REDACTED]"),
    (re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"), "[REDACTED]"),
    (re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"), "[REDACTED]"),
    (re.compile(r"\bAIza[0-9A-Za-z_-]{30,}"), "[REDACTED]"),
    (re.compile(r"\bpypi-[A-Za-z0-9_-]{20,}"), "[REDACTED]"),
    (re.compile(r"(?i)\b(bearer|token)\s+[A-Za-z0-9._~+/=-]{16,}"), r"\1 [REDACTED]"),
    (
        re.compile(r"(?i)\b([A-Za-z0-9_]*(password|passwd|secret|token|api[_-]?key)[A-Za-z0-9_]*)\s*([=:])\s*(\"[^\"]*\"|'[^']*'|[^\s\"']+)"),
        r"\1\3[REDACTED]",
    ),
    (re.compile(r"(?i)(://[^:/\s@]+:)[^@\s/]+@"), r"\1[REDACTED]@"),
]


def redact(text: str) -> str:
    for pattern, repl in _REDACTIONS:
        text = pattern.sub(repl, text)
    return text


def _clip(text: str, limit: int = MAX_FIELD) -> str:
    return text if len(text) <= limit else text[:limit] + f"... [+{len(text) - limit} chars]"


def audit_path(cfg: Optional[Config] = None) -> Path:
    env = os.environ.get(ENV_VAR)
    if env:
        return Path(env).expanduser()
    if cfg is not None and cfg.audit_log:
        return Path(cfg.audit_log).expanduser()
    return claude_home() / "hookguard" / "audit.jsonl"


def summarize_input(tool_name: str, tool_input: Any) -> str:
    """One short, redacted line describing what the tool was asked to do."""
    if not isinstance(tool_input, dict):
        return ""
    for key in ("command", "file_path", "notebook_path", "url", "pattern", "path", "query", "prompt", "description"):
        value = tool_input.get(key)
        if isinstance(value, str) and value:
            extra = ""
            if key == "pattern" and isinstance(tool_input.get("path"), str):
                extra = f" in {tool_input['path']}"
            return _clip(redact(value + extra))
    try:
        return _clip(redact(json.dumps(tool_input, sort_keys=True, default=str)))
    except (TypeError, ValueError):
        return ""


def response_ok(response: Any) -> Optional[bool]:
    if isinstance(response, dict):
        if response.get("interrupted") is True or response.get("is_error") is True:
            return False
        if response.get("success") is False:
            return False
        return True
    return None


def response_size(response: Any) -> int:
    if response is None:
        return 0
    if isinstance(response, str):
        return len(response)
    try:
        return len(json.dumps(response, default=str))
    except (TypeError, ValueError):
        return 0


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def write(record: Dict[str, Any], cfg: Optional[Config] = None) -> Path:
    path = audit_path(cfg)
    path.parent.mkdir(parents=True, exist_ok=True)
    max_bytes = cfg.audit_max_bytes if cfg is not None else 10_000_000
    try:
        if max_bytes and path.exists() and path.stat().st_size > max_bytes:
            rotated = path.with_name(path.name + ".1")
            if rotated.exists():
                rotated.unlink()
            path.rename(rotated)
    except OSError:
        pass
    line = json.dumps(record, ensure_ascii=False, sort_keys=False)
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(line + "\n")
    return path


def read(path: Path) -> Iterator[Dict[str, Any]]:
    if not path.exists():
        return
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except ValueError:
                continue
            if isinstance(rec, dict):
                yield rec


def format_record(rec: Dict[str, Any]) -> str:
    event = {"PreToolUse": "PRE ", "PostToolUse": "POST"}.get(rec.get("event", ""), (rec.get("event") or "?")[:4])
    if rec.get("event") == "PreToolUse":
        status = (rec.get("decision") or "allow").upper()
    else:
        ok = rec.get("ok")
        status = "ok" if ok is True else ("FAIL" if ok is False else "-")
    rule = f"  [{rec['rule']}]" if rec.get("rule") else ""
    return f"{rec.get('ts', '?')}  {event}  {status:<5}  {rec.get('tool', '?'):<10}  {rec.get('input', '')}{rule}"


def tail(records: List[Dict[str, Any]], n: int) -> List[Dict[str, Any]]:
    return records[-n:] if n > 0 else records
