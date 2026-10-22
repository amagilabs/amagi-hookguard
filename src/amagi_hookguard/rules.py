"""The guard rules and the evaluator that applies them to one tool call."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional

from . import gitcmd
from .config import Config
from .secretfiles import secret_match
from .shell import SimpleCommand, command_name, split_commands

ALLOW, ASK, BLOCK = "allow", "ask", "block"
_RANK = {ALLOW: 0, ASK: 1, BLOCK: 2}


@dataclass(frozen=True)
class Rule:
    id: str
    action: str
    summary: str


RULES = [
    Rule("rm-critical-path", BLOCK, "Recursive delete of /, ~, $HOME, a drive root, a system folder, `.`, `..` or `*` (rm, Remove-Item, rd /s, del /s, find -delete)."),
    Rule("chmod-critical-path", BLOCK, "Recursive chmod/chown/chgrp on /, ~ or a system folder."),
    Rule("disk-wipe", BLOCK, "mkfs, dd to a /dev device, wipefs, shred on a device, format C:, diskpart, Format-Volume, Clear-Disk, redirect into /dev/sdX."),
    Rule("fork-bomb", BLOCK, "The classic :(){ :|:& };: fork bomb."),
    Rule("git-force-push-protected", BLOCK, "Force push (-f, --force, --force-with-lease, +ref, --mirror) to a protected branch (main, master + your list), or when the branch can't be determined."),
    Rule("git-push-delete-protected", BLOCK, "Deleting a protected branch on the remote (git push --delete main, git push origin :main)."),
    Rule("secret-file-read", BLOCK, "Reading a secret file (.env, *.pem, *.key, id_rsa, .aws/credentials, .netrc, ...) with Read, Grep or a shell command (cat, type, Get-Content, grep, cp, curl -F @file, < redirect)."),
    Rule("git-force-push", ASK, "Force push to a branch that isn't protected."),
    Rule("git-reset-hard", ASK, "git reset --hard (throws away uncommitted work)."),
    Rule("git-clean-force", ASK, "git clean -f (deletes untracked files)."),
    Rule("git-discard-changes", ASK, "git checkout -- . / git checkout . / git restore . (throws away working-tree edits)."),
    Rule("pipe-to-shell", ASK, "Piping a download straight into a shell (curl | sh, wget | bash, iwr | iex)."),
    Rule("sql-drop", ASK, "DROP DATABASE / DROP TABLE / DROP SCHEMA / TRUNCATE TABLE in a shell command."),
    Rule("system-power", ASK, "shutdown, reboot, halt, poweroff, Stop-Computer, Restart-Computer."),
]
RULES_BY_ID = {r.id: r for r in RULES}

DEFAULT_SHELL_TOOLS = [r"Bash", r"PowerShell", r"mcp__.*(shell|bash|powershell|terminal|exec|run_command).*"]
DEFAULT_READ_TOOLS = [r"Read", r"Grep", r"NotebookRead", r"mcp__.*(read|get|cat|view)_?(file|text|content).*"]
PATH_KEYS = ("file_path", "path", "notebook_path", "filename", "file")


@dataclass
class Decision:
    action: str = ALLOW
    rule: Optional[str] = None
    reason: str = ""

    @property
    def blocked(self) -> bool:
        return self.action == BLOCK


def _worst(decisions: Iterable[Decision]) -> Decision:
    best = Decision()
    for d in decisions:
        if _RANK[d.action] > _RANK[best.action]:
            best = d
    return best


# ---------------------------------------------------------------- paths

SYSTEM_DIRS = {
    "bin", "boot", "dev", "etc", "home", "lib", "lib32", "lib64", "opt", "proc", "root",
    "sbin", "srv", "sys", "usr", "var", "users", "system", "library", "applications", "private",
    "mnt", "media", "snap",
}
WINDOWS_DIRS = {"windows", "users", "program files", "program files (x86)", "programdata"}
HOME_TOKENS = {"~", "$home", "${home}", "$env:userprofile", "%userprofile%", "$env:homepath", "%homepath%"}


def is_critical_path(raw: str) -> bool:
    """True for paths a recursive delete must never touch."""
    if not raw:
        return False
    p = raw.strip().strip("\"'").replace("\\", "/").lower()
    while "//" in p:
        p = p.replace("//", "/")
    if p in ("*", ".", "..", "./", "../", "./*", "../*", ".*", "./.*", "/", "/*", "/.*"):
        return True
    # strip one trailing "/" or "/*" to compare the folder itself
    base = p
    for suffix in ("/*", "/.*", "/"):
        if base.endswith(suffix) and len(base) > len(suffix):
            base = base[: -len(suffix)]
            break
    if base in HOME_TOKENS:
        return True
    if re.fullmatch(r"[a-z]:", base):
        return True
    m = re.fullmatch(r"[a-z]:/(.+)", base)
    if m:
        rest = m.group(1)
        if rest in WINDOWS_DIRS:
            return True
        if re.fullmatch(r"users/[^/*]+", rest):
            return True
        return False
    if base.startswith("/"):
        parts = [x for x in base.split("/") if x]
        if len(parts) == 1 and parts[0] in SYSTEM_DIRS:
            return True
        if len(parts) == 2 and parts[0] in ("home", "users"):
            return True
    return False


# ---------------------------------------------------------------- shell rules

READERS = {
    "cat", "tac", "less", "more", "head", "tail", "nl", "bat", "batcat", "view", "strings",
    "xxd", "hexdump", "od", "base64", "grep", "egrep", "fgrep", "rg", "ag", "awk", "gawk", "sed",
    "cut", "sort", "uniq", "diff", "type", "gc", "get-content", "cat.exe", "select-string",
    "sls", "findstr", "jq", "yq", "openssl", "gpg", "zip", "tar", "7z", "rsync", "scp",
}
COPIERS = {"cp", "copy", "copy-item", "cpi", "mv", "move", "move-item", "mi", "xcopy", "robocopy"}
RM_VERBS = {"rm", "remove-item", "ri", "del", "erase", "rd", "rmdir", "unlink"}
PS_VALUE_PARAMS = {"-include", "-exclude", "-filter", "-credential", "-stream"}
SHELL_INTERPRETERS = {
    "sh", "bash", "zsh", "dash", "ksh", "fish", "python", "python3", "perl", "ruby", "node",
    "iex", "invoke-expression", "pwsh", "powershell",
}
DOWNLOADERS = {"curl", "wget", "iwr", "invoke-webrequest", "irm", "invoke-restmethod", "fetch", "http"}
DEVICE_RE = re.compile(r"^/dev/(sd[a-z]|hd[a-z]|nvme\d|mmcblk\d|xvd[a-z]|vd[a-z]|disk\d|rdisk\d)", re.I)


def _rm_decision(cmd: SimpleCommand) -> Optional[Decision]:
    verb = cmd.verb
    if verb not in RM_VERBS:
        return None
    recursive = False
    no_preserve = False
    targets: List[str] = []
    after_dashdash = False
    skip_next = False
    for a in cmd.args:
        low = a.lower()
        if skip_next:
            skip_next = False
        elif after_dashdash:
            targets.append(a)
        elif a == "--":
            after_dashdash = True
        elif verb in ("rd", "rmdir", "del", "erase") and re.fullmatch(r"/[a-z]", low):
            recursive = recursive or low == "/s"  # cmd.exe: /s recursive, /q quiet
        elif low == "--recursive":
            recursive = True
        elif low == "--no-preserve-root":
            no_preserve = True
        elif low.startswith("--"):
            continue
        elif a.startswith("-") and len(a) > 1:
            if re.fullmatch(r"-[fiIrRdv]+", a):  # POSIX rm flag cluster: -rf, -fR, -r
                recursive = recursive or "r" in low
            elif "-recurse".startswith(low) and len(low) >= 2:  # PowerShell -Recurse / -r / -rec
                recursive = True
            elif low in PS_VALUE_PARAMS:
                skip_next = True
        else:
            targets.append(a)
    if not recursive and not no_preserve:
        return None
    for t in targets:
        if is_critical_path(t):
            return Decision(BLOCK, "rm-critical-path", f"recursive delete of '{t}'")
    if no_preserve:
        return Decision(BLOCK, "rm-critical-path", "rm --no-preserve-root")
    return None


def _find_delete(cmd: SimpleCommand) -> Optional[Decision]:
    if cmd.verb != "find":
        return None
    args = cmd.args
    deletes = "-delete" in args or any(
        a == "-exec" and i + 1 < len(args) and command_name(args[i + 1]) == "rm" for i, a in enumerate(args)
    )
    if not deletes:
        return None
    for a in args:
        if a.startswith("-") or a in ("(", "!"):
            break
        if is_critical_path(a):
            return Decision(BLOCK, "rm-critical-path", f"find {a} ... -delete")
    return None


def _chmod_decision(cmd: SimpleCommand) -> Optional[Decision]:
    if cmd.verb not in ("chmod", "chown", "chgrp"):
        return None
    args = cmd.args
    if not any(a == "--recursive" or re.fullmatch(r"-[a-zA-Z]*R[a-zA-Z]*", a) for a in args):
        return None
    for a in args:
        if not a.startswith("-") and is_critical_path(a):
            return Decision(BLOCK, "chmod-critical-path", f"{cmd.verb} -R on '{a}'")
    return None


def _disk_decision(cmd: SimpleCommand) -> Optional[Decision]:
    verb = cmd.verb
    args = cmd.args
    if verb == "mkfs" or verb.startswith("mkfs."):
        return Decision(BLOCK, "disk-wipe", f"{verb} formats a filesystem")
    if verb in ("wipefs", "diskpart", "format-volume", "clear-disk", "initialize-disk"):
        return Decision(BLOCK, "disk-wipe", f"{verb} can erase a disk")
    if verb == "dd":
        for a in args:
            if a.startswith("of=") and a[3:].startswith("/dev/") and a[3:] not in ("/dev/null", "/dev/zero", "/dev/stdout", "/dev/stderr"):
                return Decision(BLOCK, "disk-wipe", f"dd writing to {a[3:]}")
    if verb == "shred" and any(DEVICE_RE.match(a) for a in args):
        return Decision(BLOCK, "disk-wipe", "shred on a disk device")
    if verb == "format" and any(re.fullmatch(r"[a-zA-Z]:\\?", a) for a in args):
        return Decision(BLOCK, "disk-wipe", "format of a drive")
    for op, target in cmd.redirects:
        if op in (">", ">>", ">|", "&>") and DEVICE_RE.match(target):
            return Decision(BLOCK, "disk-wipe", f"redirect into {target}")
    return None


def _power_decision(cmd: SimpleCommand) -> Optional[Decision]:
    if cmd.verb in ("shutdown", "reboot", "halt", "poweroff", "stop-computer", "restart-computer"):
        return Decision(ASK, "system-power", f"{cmd.verb} stops or restarts the machine")
    if cmd.verb == "systemctl" and any(a in ("poweroff", "reboot", "halt") for a in cmd.args):
        return Decision(ASK, "system-power", "systemctl " + " ".join(cmd.args))
    return None


def _secret_args(cmd: SimpleCommand, cfg: Config) -> Optional[Decision]:
    verb = cmd.verb
    candidates: List[str] = []
    if verb in READERS:
        candidates = [a for a in cmd.args if not a.startswith("-") or "=" in a]
        candidates = [a.split("=", 1)[1] if a.startswith("-") else a for a in candidates]
    elif verb in COPIERS:
        plain = [a for a in cmd.args if not a.startswith("-")]
        candidates = plain[:-1] if len(plain) > 1 else plain
    elif verb in DOWNLOADERS:
        for i, a in enumerate(cmd.args):
            if "@" in a:
                candidates.append(a.split("@", 1)[1].split(";", 1)[0])
            if a in ("-T", "--upload-file", "-InFile", "-infile") and i + 1 < len(cmd.args):
                candidates.append(cmd.args[i + 1])
    for op, target in cmd.redirects:
        if op in ("<", "<>"):
            candidates.append(target)
    for c in candidates:
        pattern = secret_match(c, cfg.secret_globs, cfg.secret_allow_globs)
        if pattern:
            return Decision(BLOCK, "secret-file-read", f"'{c}' looks like a secret file (matches {pattern})")
    return None


def _git_decisions(cmd: SimpleCommand, cwd: Optional[str], cfg: Config) -> List[Decision]:
    if cmd.verb != "git":
        return []
    sub, args, cdir = gitcmd.split_git(cmd.args)
    out: List[Decision] = []
    if cdir:
        cwd = cdir if os.path.isabs(cdir) or not cwd else os.path.join(cwd, cdir)
    if sub == "push":
        plan = gitcmd.parse_push(args)
        protected = cfg.protected_branches
        for branch in plan.deletes:
            if gitcmd.is_protected(branch, protected):
                out.append(Decision(BLOCK, "git-push-delete-protected", f"deletes protected branch '{branch}' on the remote"))
        if plan.all_branches and plan.force:
            out.append(Decision(BLOCK, "git-force-push-protected", "force push of every branch (--mirror/--all with force)"))
        for dst, forced in plan.targets:
            if not forced:
                continue
            branch = dst
            if branch is None:
                branch = gitcmd.current_branch(cwd)
                if branch is None:
                    out.append(Decision(
                        BLOCK,
                        "git-force-push-protected",
                        "force push without a refspec and the current branch could not be determined; "
                        "name the branch explicitly (git push --force origin <branch>)",
                    ))
                    continue
            if gitcmd.is_protected(branch, protected):
                out.append(Decision(BLOCK, "git-force-push-protected", f"force push to protected branch '{branch}'"))
            else:
                out.append(Decision(ASK, "git-force-push", f"force push to '{branch}'"))
    elif sub == "reset" and "--hard" in args:
        out.append(Decision(ASK, "git-reset-hard", "git reset --hard discards uncommitted changes"))
    elif sub == "clean":
        flags = [a for a in args if a.startswith("-")]
        dry = any(a in ("-n", "--dry-run") or (not a.startswith("--") and "n" in a[1:]) for a in flags)
        forced = any(a == "--force" or (not a.startswith("--") and "f" in a[1:]) for a in flags)
        if forced and not dry:
            out.append(Decision(ASK, "git-clean-force", "git clean -f deletes untracked files"))
    elif sub in ("checkout", "restore"):
        if "--staged" in args and "--worktree" not in args and sub == "restore":
            return out
        paths = args[args.index("--") + 1:] if "--" in args else [a for a in args if not a.startswith("-")]
        if sub == "checkout" and "--" not in args:
            paths = [a for a in paths if a in (".", "*", ":/")]
        if any(p in (".", "*", ":/", "./") for p in paths):
            out.append(Decision(ASK, "git-discard-changes", f"git {sub} {' '.join(args)} discards working-tree edits"))
    return out


FORK_BOMB = re.compile(r":\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;?\s*:")
SQL_DROP = re.compile(r"\b(drop\s+(database|table|schema)|truncate\s+table)\b", re.I)
PROCESS_SUB_SHELL = re.compile(r"\b(ba|z|da|k)?sh\s+<\(\s*(curl|wget)\b", re.I)


def evaluate_command(command: str, cwd: Optional[str], cfg: Config) -> Decision:
    if not isinstance(command, str) or not command.strip():
        return Decision()
    for pattern in cfg.allow_commands:
        try:
            if re.search(pattern, command):
                return Decision(reason=f"allowed by allow_commands pattern {pattern!r}")
        except re.error:
            continue
    decisions: List[Decision] = []
    if FORK_BOMB.search(command):
        decisions.append(Decision(BLOCK, "fork-bomb", "fork bomb"))
    m = SQL_DROP.search(command)
    if m:
        decisions.append(Decision(ASK, "sql-drop", f"'{m.group(0)}' destroys data"))
    if PROCESS_SUB_SHELL.search(command):
        decisions.append(Decision(ASK, "pipe-to-shell", "runs a downloaded script"))

    commands = split_commands(command)
    work_cwd = cwd
    prev: Optional[SimpleCommand] = None
    for cmd in commands:
        if cmd.verb in ("cd", "pushd", "set-location", "sl", "chdir") and cmd.args:
            target = cmd.args[-1]
            if os.path.isabs(target) or target.startswith("~"):
                work_cwd = os.path.expanduser(target)
            elif work_cwd:
                work_cwd = os.path.join(work_cwd, target)
        for check in (_rm_decision, _find_delete, _chmod_decision, _disk_decision, _power_decision):
            d = check(cmd)
            if d:
                decisions.append(d)
        d = _secret_args(cmd, cfg)
        if d:
            decisions.append(d)
        decisions.extend(_git_decisions(cmd, work_cwd, cfg))
        if (
            prev is not None
            and cmd.after in ("|", "|&")
            and cmd.verb in SHELL_INTERPRETERS
            and prev.verb in DOWNLOADERS
            and not [a for a in cmd.args if not a.startswith("-")]
        ):
            decisions.append(Decision(ASK, "pipe-to-shell", f"{prev.verb} output piped into {cmd.verb}"))
        prev = cmd
    decisions = [d for d in decisions if d.rule not in cfg.disabled_rules]
    return _worst(decisions)


def _tool_matches(name: str, patterns: List[str]) -> bool:
    for p in patterns:
        try:
            if re.fullmatch(p, name):
                return True
        except re.error:
            if p == name:
                return True
    return False


def evaluate(tool_name: str, tool_input: Any, cwd: Optional[str], cfg: Config) -> Decision:
    """Decide what to do with one PreToolUse call."""
    if not isinstance(tool_input, dict):
        return Decision()
    decision = Decision()
    if _tool_matches(tool_name, DEFAULT_SHELL_TOOLS) and isinstance(tool_input.get("command"), str):
        decision = evaluate_command(tool_input["command"], cwd, cfg)
    elif _tool_matches(tool_name, DEFAULT_READ_TOOLS) and "secret-file-read" not in cfg.disabled_rules:
        for key in PATH_KEYS:
            value = tool_input.get(key)
            if isinstance(value, str):
                pattern = secret_match(value, cfg.secret_globs, cfg.secret_allow_globs)
                if pattern:
                    decision = Decision(BLOCK, "secret-file-read", f"'{value}' looks like a secret file (matches {pattern})")
                    break
        glob = tool_input.get("glob")
        if decision.action == ALLOW and isinstance(glob, str):
            bare = glob.replace("**/", "").replace("*", "").strip("{}")
            pattern = secret_match(bare, cfg.secret_globs, cfg.secret_allow_globs) if bare else None
            if pattern:
                decision = Decision(BLOCK, "secret-file-read", f"glob '{glob}' targets secret files (matches {pattern})")
    if decision.action == ASK and cfg.ask_as_block:
        decision = Decision(BLOCK, decision.rule, decision.reason + " (ask_as_block is on)")
    return decision
