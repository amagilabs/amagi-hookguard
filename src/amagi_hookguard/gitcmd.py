"""Read `git ...` argument lists: which subcommand, and what a push would overwrite."""

from __future__ import annotations

import fnmatch
import os
import subprocess
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

# git global options that take a separate value.
GLOBAL_WITH_VALUE = {"-C", "-c", "--git-dir", "--work-tree", "--namespace", "--exec-path", "--config-env"}
# git push options that take a separate value.
PUSH_WITH_VALUE = {"-o", "--push-option", "--receive-pack", "--exec", "--repo", "--signed"}


def split_git(args: List[str]) -> Tuple[Optional[str], List[str], Optional[str]]:
    """Return (subcommand, subcommand args, -C directory) for the args after `git`."""
    i = 0
    cdir: Optional[str] = None
    while i < len(args):
        a = args[i]
        if a == "-C" and i + 1 < len(args):
            cdir = args[i + 1] if cdir is None else os.path.join(cdir, args[i + 1])
            i += 2
            continue
        if a in GLOBAL_WITH_VALUE:
            i += 2
            continue
        if a.startswith("-"):
            i += 1
            continue
        return a, args[i + 1:], cdir
    return None, [], cdir


@dataclass
class PushPlan:
    force: bool = False  # whole push is forced (-f, --force, --force-with-lease, --mirror)
    delete: bool = False
    all_branches: bool = False  # --all / --mirror
    remote: Optional[str] = None
    # (destination branch or None for "current branch", forced?)
    targets: List[Tuple[Optional[str], bool]] = field(default_factory=list)
    deletes: List[str] = field(default_factory=list)


def _short(ref: str) -> str:
    for prefix in ("refs/heads/", "heads/"):
        if ref.startswith(prefix):
            return ref[len(prefix):]
    return ref


def parse_push(args: List[str]) -> PushPlan:
    plan = PushPlan()
    positional: List[str] = []
    i = 0
    only_positional = False
    while i < len(args):
        a = args[i]
        if only_positional or not a.startswith("-") or a == "-":
            positional.append(a)
            i += 1
            continue
        if a == "--":
            only_positional = True
        elif a in ("--force", "--force-with-lease", "--force-if-includes") or a.startswith("--force-with-lease="):
            plan.force = True
        elif a == "--mirror":
            plan.force = True
            plan.all_branches = True
        elif a == "--all" or a == "--branches":
            plan.all_branches = True
        elif a in ("--delete",):
            plan.delete = True
        elif a.startswith("--repo="):
            plan.remote = a.split("=", 1)[1]
        elif a in PUSH_WITH_VALUE:
            if a == "--repo" and i + 1 < len(args):
                plan.remote = args[i + 1]
            i += 1
        elif not a.startswith("--"):
            cluster = a[1:]
            # -o takes a value: stop reading the cluster there.
            if "o" in cluster:
                head, _, tail = cluster.partition("o")
                cluster = head
                if not tail:
                    i += 1
            if "f" in cluster:
                plan.force = True
            if "d" in cluster:
                plan.delete = True
        i += 1

    if plan.remote is None and positional:
        plan.remote = positional.pop(0)
    refspecs = positional
    for spec in refspecs:
        forced = plan.force
        if spec.startswith("+"):
            forced = True
            spec = spec[1:]
        if plan.delete:
            plan.deletes.append(_short(spec))
            continue
        if ":" in spec:
            src, dst = spec.split(":", 1)
            if not src:
                plan.deletes.append(_short(dst))
                continue
            if not dst:
                dst = src
        else:
            dst = spec
        dst = _short(dst)
        plan.targets.append((None if dst == "HEAD" else dst, forced))
    if not refspecs and not plan.delete and not plan.all_branches:
        plan.targets.append((None, plan.force))
    return plan


def is_protected(branch: str, patterns: List[str]) -> bool:
    return any(fnmatch.fnmatchcase(branch, p) for p in patterns)


def current_branch(cwd: Optional[str]) -> Optional[str]:
    """Branch checked out in `cwd`, or None when unknown (no git, detached, not a repo)."""
    if not cwd or not os.path.isdir(cwd):
        return None
    try:
        res = subprocess.run(
            ["git", "-C", cwd, "symbolic-ref", "--quiet", "--short", "HEAD"],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    name = res.stdout.strip()
    return name if res.returncode == 0 and name else None
