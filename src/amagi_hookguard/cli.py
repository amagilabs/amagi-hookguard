"""Command-line interface."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import List, Optional

from . import __version__

# Everything else is imported inside the handlers: `hook` runs on every tool
# call, so it should load as little as possible.

PROG = "amagi-hookguard"


def _parser() -> "argparse.ArgumentParser":
    import argparse

    p = argparse.ArgumentParser(
        prog=PROG,
        description="Guardrail hooks for Claude Code: block destructive commands, secret-file reads and "
        "force pushes to main, log every tool call, and check your hook wiring.",
    )
    p.add_argument("--version", action="version", version=f"{PROG} {__version__}")
    sub = p.add_subparsers(dest="cmd", metavar="COMMAND")

    sub.add_parser("hook", help="run as a Claude Code hook (reads one event as JSON on stdin)")

    pi = sub.add_parser("install", help="add hookguard to a settings.json (backs up the old file)")
    pi.add_argument("--scope", choices=["user", "project", "local"], default="user",
                    help="user = ~/.claude/settings.json (default), project = .claude/settings.json, "
                    "local = .claude/settings.local.json")
    pi.add_argument("--settings", metavar="PATH", help="write to this settings file instead of a scope")
    pi.add_argument("--project", metavar="DIR", help="project folder for project/local scope (default: current folder)")
    pi.add_argument("--absolute", action="store_true", help="write the full path to the executable instead of relying on PATH")
    pi.add_argument("--dry-run", action="store_true", help="print the result without writing")

    pu = sub.add_parser("uninstall", help="remove hookguard from a settings.json")
    pu.add_argument("--scope", choices=["user", "project", "local"], default="user")
    pu.add_argument("--settings", metavar="PATH")
    pu.add_argument("--project", metavar="DIR")
    pu.add_argument("--dry-run", action="store_true")

    pd = sub.add_parser("doctor", help="check hook wiring in your Claude Code settings files")
    pd.add_argument("--settings", metavar="PATH", action="append", help="check only this file (repeatable)")
    pd.add_argument("--project", metavar="DIR", help="project folder (default: current folder)")
    pd.add_argument("--no-exec", action="store_true", help="don't run the wired hook command with sample events")
    pd.add_argument("--json", action="store_true", help="machine-readable output")

    pc = sub.add_parser("check", help="show what hookguard would do with a command or file read")
    pc.add_argument("command", nargs="?", help="shell command to test (as the Bash tool would run it)")
    pc.add_argument("--read", metavar="PATH", help="test a Read of this file instead")
    pc.add_argument("--tool", metavar="NAME", help="tool name for --input (e.g. Grep, PowerShell)")
    pc.add_argument("--input", metavar="JSON", help="raw tool_input JSON for --tool")
    pc.add_argument("--cwd", metavar="DIR", help="working folder for git branch lookups (default: current folder)")

    sub.add_parser("rules", help="list the rules and what each one does")

    pl = sub.add_parser("log", help="show the audit log")
    pl.add_argument("-n", "--tail", type=int, default=20, metavar="N", help="last N entries (0 = all, default 20)")
    pl.add_argument("--blocked", action="store_true", help="only calls hookguard blocked or flagged")
    pl.add_argument("--session", metavar="ID", help="only this session id")
    pl.add_argument("--json", action="store_true", help="raw JSON lines")
    pl.add_argument("--path", action="store_true", help="print the audit log path and exit")
    return p


def _settings_target(args) -> Path:
    from . import settings

    if args.settings:
        return Path(args.settings).expanduser()
    return settings.scope_path(args.scope, args.project)


def cmd_install(args) -> int:
    from . import doctor, settings

    path = _settings_target(args)
    command = settings.hook_command(args.absolute)
    try:
        text, backup = settings.install(path, command, dry_run=args.dry_run)
    except (ValueError, json.JSONDecodeError) as exc:
        print(f"{PROG}: {path} is not valid settings JSON, nothing changed: {exc}", file=sys.stderr)
        return 1
    shown = doctor.display_path(path)
    if args.dry_run:
        print(f"Would write {shown}:\n")
        print(text)
        return 0
    print(f"Wired hookguard into {shown} (PreToolUse + PostToolUse, matcher \"*\", command `{command}`).")
    if backup:
        print(f"Previous file saved as {doctor.display_path(backup)}")
    print("Restart Claude Code (or open /hooks) so it picks up the change, then run: amagi-hookguard doctor")
    return 0


def cmd_uninstall(args) -> int:
    from . import doctor, settings

    path = _settings_target(args)
    try:
        removed, backup = settings.uninstall(path, dry_run=args.dry_run)
    except (ValueError, json.JSONDecodeError) as exc:
        print(f"{PROG}: {path} is not valid settings JSON, nothing changed: {exc}", file=sys.stderr)
        return 1
    shown = doctor.display_path(path)
    if not removed:
        print(f"No hookguard hooks found in {shown}.")
        return 0
    verb = "Would remove" if args.dry_run else "Removed"
    print(f"{verb} {removed} hookguard hook(s) from {shown}.")
    if backup:
        print(f"Previous file saved as {doctor.display_path(backup)}")
    return 0


def cmd_doctor(args) -> int:
    from . import doctor

    sections = doctor.run_doctor(args.project, args.settings, execute=not args.no_exec)
    print(doctor.to_json(sections) if args.json else doctor.render(sections))
    return 1 if doctor.counts(sections)[doctor.FAIL] else 0


def cmd_check(args) -> int:
    from .config import load_config
    from .rules import ASK, BLOCK, evaluate

    cwd = os.path.abspath(args.cwd or os.getcwd())
    if args.read:
        tool, tool_input = "Read", {"file_path": args.read}
    elif args.tool:
        tool = args.tool
        try:
            tool_input = json.loads(args.input or "{}")
        except ValueError as exc:
            print(f"{PROG}: --input is not valid JSON: {exc}", file=sys.stderr)
            return 1
        if args.command and "command" not in tool_input:
            tool_input["command"] = args.command
    elif args.command:
        tool, tool_input = "Bash", {"command": args.command}
    else:
        print(f"{PROG} check: give a command, --read PATH, or --tool NAME --input JSON", file=sys.stderr)
        return 1
    decision = evaluate(tool, tool_input, cwd, load_config(cwd))
    label = {BLOCK: "BLOCK", ASK: "ASK"}.get(decision.action, "allow")
    shown = tool_input.get("command") or tool_input.get("file_path") or json.dumps(tool_input)
    line = f"{label:<5}  {tool}: {shown}"
    if decision.rule:
        line += f"\n       [{decision.rule}] {decision.reason}"
    print(line)
    return {BLOCK: 2, ASK: 3}.get(decision.action, 0)


def cmd_rules(args) -> int:
    from .rules import RULES

    for r in RULES:
        print(f"{r.action.upper():<5}  {r.id:<26}  {r.summary}")
    print("\nTurn a rule off with \"disabled_rules\": [\"<id>\"] in ~/.claude/hookguard.json.")
    return 0


def cmd_log(args) -> int:
    from . import audit, doctor
    from .config import load_config
    from .rules import ASK, BLOCK

    path = audit.audit_path(load_config(os.getcwd()))
    if args.path:
        print(path)
        return 0
    records = list(audit.read(path))
    if args.blocked:
        records = [r for r in records if r.get("decision") in (BLOCK, ASK)]
    if args.session:
        records = [r for r in records if r.get("session") == args.session]
    records = audit.tail(records, args.tail)
    if not records:
        print(f"No entries in {doctor.display_path(path)}.")
        return 0
    for rec in records:
        print(json.dumps(rec, ensure_ascii=False) if args.json else audit.format_record(rec))
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass
    if argv is None:
        argv = sys.argv[1:]
    # Fast path for the hook: on Python 3.13+ argparse alone pulls in ~0.3 s of
    # imports (_colorize, dataclasses, inspect, shutil), paid on every tool call.
    if list(argv) == ["hook"]:
        from . import hook

        return hook.run()
    args = _parser().parse_args(argv)
    if args.cmd is None:
        _parser().print_help()
        return 0
    if args.cmd == "hook":
        from . import hook

        return hook.run()
    handlers = {
        "install": cmd_install,
        "uninstall": cmd_uninstall,
        "doctor": cmd_doctor,
        "check": cmd_check,
        "rules": cmd_rules,
        "log": cmd_log,
    }
    return handlers[args.cmd](args)
