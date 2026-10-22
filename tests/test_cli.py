import json
import subprocess

import pytest

from amagi_hookguard import __version__, audit
from amagi_hookguard.cli import main

from conftest import HOOK_CMD


def test_version_and_help():
    res = subprocess.run(HOOK_CMD + ["--version"], capture_output=True, text=True, timeout=60)
    assert res.returncode == 0 and res.stdout.strip() == f"amagi-hookguard {__version__}"
    res = subprocess.run(HOOK_CMD + ["--help"], capture_output=True, text=True, timeout=60)
    assert res.returncode == 0
    for sub in ("hook", "install", "uninstall", "doctor", "check", "rules", "log"):
        assert sub in res.stdout


def test_no_args_prints_help(capsys):
    assert main([]) == 0
    assert "usage:" in capsys.readouterr().out


def test_bad_subcommand_exits_2():
    with pytest.raises(SystemExit) as exc:
        main(["frobnicate"])
    assert exc.value.code == 2


@pytest.mark.parametrize("argv,code,text", [
    (["check", "rm -rf ~"], 2, "BLOCK"),
    (["check", "git push -f origin feature/x"], 3, "ASK"),
    (["check", "ls"], 0, "allow"),
    (["check", "--read", "~/.ssh/id_rsa"], 2, "secret-file-read"),
    (["check", "--tool", "Grep", "--input", '{"pattern": "KEY", "path": ".env"}'], 2, "secret-file-read"),
    (["check", "--tool", "Grep", "--input", "{nope"], 1, ""),
    (["check"], 1, ""),
])
def test_check(capsys, argv, code, text):
    assert main(argv) == code
    assert text in capsys.readouterr().out


def test_rules_lists_every_rule(capsys):
    assert main(["rules"]) == 0
    out = capsys.readouterr().out
    assert "rm-critical-path" in out and "git-force-push-protected" in out and "secret-file-read" in out


def test_install_doctor_uninstall_round_trip(tmp_path, capsys):
    path = tmp_path / "settings.json"
    assert main(["install", "--settings", str(path), "--absolute"]) == 0
    assert "Wired hookguard" in capsys.readouterr().out
    assert json.loads(path.read_text(encoding="utf-8"))["hooks"]["PreToolUse"]
    assert main(["doctor", "--settings", str(path)]) == 0
    assert "Result: PASS" in capsys.readouterr().out
    assert main(["uninstall", "--settings", str(path)]) == 0
    assert "Removed 2" in capsys.readouterr().out
    assert main(["doctor", "--settings", str(path), "--no-exec"]) == 1


def test_install_dry_run_and_broken_file(tmp_path, capsys):
    path = tmp_path / "settings.json"
    assert main(["install", "--settings", str(path), "--dry-run"]) == 0
    assert "Would write" in capsys.readouterr().out and not path.exists()
    path.write_text("{ broken", encoding="utf-8")
    assert main(["install", "--settings", str(path)]) == 1
    assert "nothing changed" in capsys.readouterr().err


def test_doctor_json(tmp_path, capsys):
    path = tmp_path / "settings.json"
    path.write_text('{"hooks": {"pretooluse": []}}', encoding="utf-8")
    assert main(["doctor", "--settings", str(path), "--json", "--no-exec"]) == 1
    assert json.loads(capsys.readouterr().out)["result"] == "FAIL"


def test_log(capsys, audit_file):
    assert main(["log"]) == 0
    assert "No entries" in capsys.readouterr().out
    audit.write({"ts": "2026-10-22T10:00:00Z", "event": "PostToolUse", "session": "a", "tool": "Bash", "input": "ls", "ok": True})
    audit.write({"ts": "2026-10-22T10:00:01Z", "event": "PreToolUse", "session": "b", "tool": "Bash",
                 "input": "rm -rf ~", "decision": "block", "rule": "rm-critical-path"})
    assert main(["log"]) == 0
    out = capsys.readouterr().out
    assert "ls" in out and "rm-critical-path" in out
    assert main(["log", "--blocked"]) == 0
    out = capsys.readouterr().out
    assert "rm -rf ~" in out and "  ls" not in out
    assert main(["log", "--session", "a", "--json"]) == 0
    lines = capsys.readouterr().out.strip().splitlines()
    assert len(lines) == 1 and json.loads(lines[0])["session"] == "a"
    assert main(["log", "--path"]) == 0
    assert capsys.readouterr().out.strip() == str(audit_file)
