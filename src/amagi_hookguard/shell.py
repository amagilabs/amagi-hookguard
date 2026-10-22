"""Split a shell command line into simple commands.

This is a best-effort reader for the commands an agent typically runs
(bash, sh, PowerShell, cmd). It is not a full shell parser. It splits on
`;`, `&&`, `||`, `|`, `&`, newlines and subshell parentheses, records
redirections, peels off wrappers such as `sudo`, `env`, `nohup` and
`timeout`, and recurses into `bash -c "..."`, `pwsh -Command "..."`,
`powershell -EncodedCommand ...`, `cmd /c ...` and `eval "..."`.
"""

from __future__ import annotations

import base64
import re
import shlex
from typing import List, Optional, Tuple

SEPARATORS = {";", "&&", "||", "|", "&", "|&", "(", ")", ";;", "{", "}"}
REDIRECTS = {">", ">>", "<", "<<", "<<<", ">&", "<&", "&>", "&>>", ">|", "<>"}
# Words that start a compound command; the real command follows them.
LEADING_KEYWORDS = {"if", "then", "else", "elif", "do", "while", "until", "!", "time"}

SHELLS = {"bash", "sh", "zsh", "dash", "ksh", "fish", "ash"}
POWERSHELLS = {"powershell", "pwsh"}
MAX_DEPTH = 5


class SimpleCommand:
    """One command in a pipeline or list, after wrappers are removed."""

    __slots__ = ("argv", "redirects", "after")

    def __init__(self, argv: List[str], redirects: Optional[List[Tuple[str, str]]] = None, after: str = "") -> None:
        self.argv = argv
        self.redirects = redirects if redirects is not None else []
        # Separator that came before this command ("" for the first one).
        self.after = after

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, SimpleCommand):
            return NotImplemented
        return (self.argv, self.redirects, self.after) == (other.argv, other.redirects, other.after)

    def __repr__(self) -> str:
        return f"SimpleCommand({self.argv!r}, {self.redirects!r}, {self.after!r})"

    @property
    def verb(self) -> str:
        return command_name(self.argv[0]) if self.argv else ""

    @property
    def args(self) -> List[str]:
        return self.argv[1:]


def command_name(word: str) -> str:
    """`/usr/bin/rm` -> `rm`, `C:\\Git\\cmd\\git.exe` -> `git`, `Remove-Item` -> `remove-item`."""
    name = word.replace("\\", "/").rsplit("/", 1)[-1].lower()
    for ext in (".exe", ".cmd", ".bat", ".com"):
        if name.endswith(ext):
            name = name[: -len(ext)]
            break
    return name


def tokenize(command: str) -> List[str]:
    """Tokenize with shell quoting rules; backslashes stay literal (Windows paths)."""
    text = command.replace("\\\r\n", " ").replace("\\\n", " ")
    text = text.replace("\r\n", "\n").replace("\n", " ; ").replace("`", " ; ")
    for suffix in ("", '"', "'"):
        lexer = shlex.shlex(text + suffix, posix=True, punctuation_chars=True)
        lexer.whitespace_split = True
        lexer.escape = ""
        lexer.commenters = ""
        try:
            return list(lexer)
        except ValueError:
            continue
    return text.split()


def split_commands(command: str, _depth: int = 0) -> List[SimpleCommand]:
    """Return every simple command in `command`, including nested `-c` scripts."""
    out: List[SimpleCommand] = []
    if _depth > MAX_DEPTH or not command or not command.strip():
        return out
    tokens = tokenize(command)
    current: List[str] = []
    redirects: List[Tuple[str, str]] = []
    sep = ""
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok in SEPARATORS:
            _emit(out, current, redirects, sep, _depth)
            current, redirects = [], []
            if tok not in ("(", ")", "{", "}"):
                sep = tok
            i += 1
            continue
        if tok in REDIRECTS:
            # `2>` arrives as `2`, `>`; drop the fd number.
            if current and current[-1].isdigit():
                current.pop()
            target = tokens[i + 1] if i + 1 < len(tokens) else ""
            if target in SEPARATORS or target in REDIRECTS:
                target = ""
            else:
                i += 1
            redirects.append((tok, target))
            i += 1
            continue
        current.append(tok)
        i += 1
    _emit(out, current, redirects, sep, _depth)
    return out


def _emit(out: List[SimpleCommand], argv: List[str], redirects, sep: str, depth: int) -> None:
    argv = unwrap(list(argv))
    if not argv and not redirects:
        return
    cmd = SimpleCommand(argv=argv, redirects=list(redirects), after=sep)
    out.append(cmd)
    inner = nested_script(argv)
    if inner is not None:
        for sub in split_commands(inner, depth + 1):
            out.append(sub)


def unwrap(argv: List[str]) -> List[str]:
    """Strip env assignments, compound keywords and wrapper commands."""
    for _ in range(10):
        while argv and (argv[0] in LEADING_KEYWORDS or _is_assignment(argv[0])):
            argv = argv[1:]
        if not argv:
            return argv
        name = command_name(argv[0])
        rest = argv[1:]
        if name in ("sudo", "doas"):
            argv = _skip_options(rest, takes_value={"-u", "-g", "-h", "-p", "-C", "-D", "-r", "-t", "-U"})
        elif name == "env":
            rest = _skip_options(rest, takes_value={"-u", "-C", "-S", "--unset", "--chdir"})
            while rest and _is_assignment(rest[0]):
                rest = rest[1:]
            argv = rest
        elif name in ("nohup", "command", "builtin", "exec", "stdbuf", "caffeinate", "unbuffer"):
            argv = _skip_options(rest, takes_value=set())
        elif name == "nice":
            argv = _skip_options(rest, takes_value={"-n"})
        elif name == "ionice":
            argv = _skip_options(rest, takes_value={"-c", "-n", "-p"})
        elif name == "timeout":
            rest = _skip_options(rest, takes_value={"-s", "-k", "--signal", "--kill-after"})
            argv = rest[1:] if rest else rest
        elif name == "xargs":
            argv = _skip_options(rest, takes_value={"-I", "-n", "-P", "-L", "-d", "-E", "-s", "-a"})
        else:
            return argv
    return argv


def _skip_options(args: List[str], takes_value: set) -> List[str]:
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--":
            return args[i + 1:]
        if not a.startswith("-") or a == "-":
            break
        i += 2 if a in takes_value else 1
    return args[i:]


def _is_assignment(word: str) -> bool:
    return bool(re.match(r"^[A-Za-z_][A-Za-z0-9_]*\+?=", word))


def nested_script(argv: List[str]) -> Optional[str]:
    """If argv runs a script given inline (`bash -c`, `pwsh -c`, `cmd /c`, `eval`), return it."""
    if not argv:
        return None
    name = command_name(argv[0])
    args = argv[1:]
    if name in SHELLS:
        for i, a in enumerate(args):
            if a.startswith("-") and not a.startswith("--") and "c" in a[1:]:
                return args[i + 1] if i + 1 < len(args) else None
        return None
    if name in POWERSHELLS:
        for i, a in enumerate(args):
            low = a.lower()
            if low in ("-command", "-c", "/command", "/c") or (
                low.startswith("-com") and "-command".startswith(low)
            ):
                return " ".join(args[i + 1:]) or None
            if low in ("-encodedcommand", "-enc", "-e", "-ec") or (
                low.startswith("-en") and "-encodedcommand".startswith(low)
            ):
                if i + 1 < len(args):
                    try:
                        return base64.b64decode(args[i + 1]).decode("utf-16-le")
                    except (ValueError, UnicodeDecodeError):
                        return None
        return None
    if name == "cmd":
        for i, a in enumerate(args):
            if a.lower() in ("/c", "/k", "/r"):
                return " ".join(args[i + 1:]) or None
        return None
    if name == "eval":
        return " ".join(args) or None
    return None
