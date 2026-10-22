import pytest

from amagi_hookguard.config import Config
from amagi_hookguard.gitcmd import current_branch, is_protected, parse_push, split_git
from amagi_hookguard.rules import ALLOW, ASK, BLOCK, evaluate_command


def test_split_git_handles_global_options():
    assert split_git(["-C", "repo", "-c", "a=b", "push", "-f"]) == ("push", ["-f"], "repo")
    assert split_git(["--no-pager", "log"])[0] == "log"


@pytest.mark.parametrize("args,force,targets", [
    (["origin", "main"], False, [("main", False)]),
    (["-f", "origin", "main"], True, [("main", True)]),
    (["--force-with-lease", "origin", "main"], True, [("main", True)]),
    (["--force-with-lease=main:abc", "origin", "main"], True, [("main", True)]),
    (["-uf", "origin", "dev"], True, [("dev", True)]),
    (["origin", "+main"], False, [("main", True)]),
    (["origin", "HEAD:refs/heads/main"], False, [("main", False)]),
    (["origin", "+feature:main"], False, [("main", True)]),
    (["--force"], True, [(None, True)]),
])
def test_parse_push(args, force, targets):
    plan = parse_push(args)
    assert plan.force == force
    assert plan.targets == targets


def test_parse_push_deletes_and_mirror():
    assert parse_push(["origin", "--delete", "main"]).deletes == ["main"]
    assert parse_push(["origin", ":main"]).deletes == ["main"]
    assert parse_push(["-d", "origin", "old"]).deletes == ["old"]
    plan = parse_push(["--mirror", "backup"])
    assert plan.force and plan.all_branches


def test_is_protected_globs():
    assert is_protected("main", ["main", "master"])
    assert is_protected("release/1.2", ["release/*"])
    assert not is_protected("feature/x", ["main", "release/*"])


@pytest.mark.parametrize("command,action,rule", [
    ("git push --force origin main", BLOCK, "git-force-push-protected"),
    ("git push -f origin master", BLOCK, "git-force-push-protected"),
    ("git push origin +main", BLOCK, "git-force-push-protected"),
    ("git push --force-with-lease origin HEAD:main", BLOCK, "git-force-push-protected"),
    ("git push --mirror backup", BLOCK, "git-force-push-protected"),
    ("git push --all --force origin", BLOCK, "git-force-push-protected"),
    ("git push origin --delete main", BLOCK, "git-push-delete-protected"),
    ("git push origin :master", BLOCK, "git-push-delete-protected"),
    ("git push -f origin feature/x", ASK, "git-force-push"),
    ("git push origin main", ALLOW, None),
    ("git push origin --delete feature/old", ALLOW, None),
    ("git push --tags", ALLOW, None),
])
def test_push_rules(command, action, rule):
    d = evaluate_command(command, None, Config())
    assert (d.action, d.rule) == (action, rule), command


def test_custom_protected_branches():
    cfg = Config()
    cfg.protected_branches = ["main", "release/*"]
    d = evaluate_command("git push -f origin release/2.0", None, cfg)
    assert d.action == BLOCK


def test_bare_force_push_uses_current_branch(git_repo):
    assert current_branch(str(git_repo)) == "main"
    d = evaluate_command("git push --force", str(git_repo), Config())
    assert (d.action, d.rule) == (BLOCK, "git-force-push-protected")
    git_repo.checkout("feature/y")
    assert current_branch(str(git_repo)) == "feature/y"
    d = evaluate_command("git push --force", str(git_repo), Config())
    assert (d.action, d.rule) == (ASK, "git-force-push")


def test_bare_force_push_follows_cd_and_dash_C(git_repo, tmp_path):
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    d = evaluate_command(f'cd "{git_repo}" && git push -f', str(elsewhere), Config())
    assert d.action == BLOCK
    d = evaluate_command(f'git -C "{git_repo}" push -f', str(elsewhere), Config())
    assert d.action == BLOCK


def test_bare_force_push_with_unknown_branch_is_blocked(tmp_path):
    d = evaluate_command("git push --force", str(tmp_path), Config())
    assert d.action == BLOCK
    assert "could not be determined" in d.reason


def test_current_branch_outside_repo(tmp_path):
    assert current_branch(str(tmp_path)) is None
    assert current_branch(None) is None
