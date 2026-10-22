import io
import json
import subprocess
from pathlib import Path

import pytest

from amagi_hookguard import audit, hook

from conftest import HOOK_CMD

FIXTURES = Path(__file__).parent / "fixtures" / "events"


def call(event, raw=None):
    out, err = io.StringIO(), io.StringIO()
    code = hook.run(io.StringIO(raw if raw is not None else json.dumps(event)), out, err)
    return code, out.getvalue(), err.getvalue()


def pre(tool, tool_input, **extra):
    event = {"hook_event_name": "PreToolUse", "session_id": "s1", "cwd": None, "tool_name": tool, "tool_input": tool_input}
    event.update(extra)
    return event


def test_block_exits_2_with_reason(audit_file):
    code, out, err = call(pre("Bash", {"command": "rm -rf ~"}))
    assert code == 2 and out == ""
    assert "rm-critical-path" in err and "blocked" in err
    (rec,) = list(audit.read(audit_file))
    assert rec["decision"] == "block" and rec["rule"] == "rm-critical-path" and rec["input"] == "rm -rf ~"


def test_ask_prints_permission_decision(audit_file):
    code, out, err = call(pre("Bash", {"command": "git reset --hard"}))
    assert code == 0 and err == ""
    payload = json.loads(out)["hookSpecificOutput"]
    assert payload["hookEventName"] == "PreToolUse"
    assert payload["permissionDecision"] == "ask"
    assert "git-reset-hard" in payload["permissionDecisionReason"]
    assert list(audit.read(audit_file))[0]["decision"] == "ask"


def test_allow_is_silent_and_not_logged(audit_file):
    assert call(pre("Bash", {"command": "ls -la"})) == (0, "", "")
    assert not audit_file.exists()


def test_read_of_secret_file_is_blocked():
    code, _, err = call(pre("Read", {"file_path": "/repo/.env"}))
    assert code == 2 and "secret-file-read" in err


def test_post_tool_use_is_logged_with_redaction(audit_file):
    token = "gh" + "p_" + "Z9y8" * 9
    event = {
        "hook_event_name": "PostToolUse", "session_id": "s2", "cwd": "/repo", "tool_name": "Bash",
        "tool_input": {"command": f"curl -H 'Authorization: token {token}' https://api.github.com"},
        "tool_response": {"stdout": "{}", "stderr": "", "interrupted": False},
    }
    assert call(event) == (0, "", "")
    (rec,) = list(audit.read(audit_file))
    assert rec["event"] == "PostToolUse" and rec["ok"] is True and rec["session"] == "s2"
    assert token not in audit_file.read_text(encoding="utf-8")


def test_failure_event_is_logged_as_not_ok(audit_file):
    event = {"hook_event_name": "PostToolUseFailure", "tool_name": "Bash", "tool_input": {"command": "false"}}
    assert call(event)[0] == 0
    assert list(audit.read(audit_file))[0]["ok"] is False


def test_bad_input_is_a_non_blocking_error():
    code, _, err = call(None, raw="not json")
    assert code == 1 and "could not parse" in err
    assert call(None, raw="[1, 2]")[0] == 1


def test_internal_error_fails_open_unless_fail_closed(monkeypatch, isolated_home):
    def boom(*a, **k):
        raise RuntimeError("bug")

    monkeypatch.setattr(hook, "evaluate", boom)
    code, _, err = call(pre("Bash", {"command": "ls"}))
    assert code == 1 and "internal error" in err
    (isolated_home / "hookguard.json").write_text('{"fail_closed": true}', encoding="utf-8")
    code, _, err = call(pre("Bash", {"command": "ls"}))
    assert code == 2 and "fail_closed" in err


def test_unwritable_audit_log_does_not_break_blocking(monkeypatch, tmp_path):
    monkeypatch.setenv(audit.ENV_VAR, str(tmp_path))  # a directory, so open() fails
    code, _, err = call(pre("Bash", {"command": "rm -rf ~"}))
    assert code == 2 and "could not write audit log" in err


@pytest.mark.parametrize("name,want_code,want_text", [
    ("pre_bash_rm_home.json", 2, "rm-critical-path"),
    ("pre_bash_force_push_main.json", 2, "git-force-push-protected"),
    ("pre_read_env.json", 2, "secret-file-read"),
    ("pre_powershell_remove_drive.json", 2, "rm-critical-path"),
    ("pre_bash_curl_pipe_sh.json", 0, '"permissionDecision": "ask"'),
    ("pre_bash_safe.json", 0, ""),
    ("post_bash.json", 0, ""),
])
def test_fixture_events_through_a_real_process(name, want_code, want_text, audit_file):
    data = (FIXTURES / name).read_bytes()
    res = subprocess.run(HOOK_CMD + ["hook"], input=data, capture_output=True, timeout=60)
    assert res.returncode == want_code, res.stderr
    assert want_text in (res.stdout + res.stderr).decode("utf-8")
    if name == "post_bash.json":
        assert list(audit.read(audit_file))[0]["event"] == "PostToolUse"
