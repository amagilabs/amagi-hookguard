import json
import sys
from pathlib import Path

import pytest

from amagi_hookguard import doctor, settings

PY_HOOK = f'"{Path(sys.executable).as_posix()}" -m amagi_hookguard hook'


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def findings(sections, code=None, level=None):
    return [f for s in sections for f in s.findings
            if (code is None or f.code == code) and (level is None or f.level == level)]


# ------------------------------------------------------------- install

def test_install_into_missing_file(tmp_path):
    path = tmp_path / ".claude" / "settings.json"
    text, backup = settings.install(path, "amagi-hookguard hook")
    assert backup is None
    data = read(path)
    for event in ("PreToolUse", "PostToolUse"):
        (group,) = data["hooks"][event]
        assert group["matcher"] == "*"
        assert group["hooks"] == [{"type": "command", "command": "amagi-hookguard hook", "timeout": 10}]


def test_install_keeps_other_settings_and_hooks_and_backs_up(tmp_path):
    path = tmp_path / "settings.json"
    original = {
        "model": "opus",
        "permissions": {"allow": ["Bash(npm test)"]},
        "hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "my-linter"}]}],
                  "Stop": [{"hooks": [{"type": "command", "command": "notify-send done"}]}]},
    }
    path.write_text(json.dumps(original), encoding="utf-8")
    _, backup = settings.install(path, "amagi-hookguard hook")
    assert read(backup) == original
    data = read(path)
    assert data["model"] == "opus" and data["permissions"] == original["permissions"]
    assert data["hooks"]["Stop"] == original["hooks"]["Stop"]
    commands = [h["command"] for g in data["hooks"]["PreToolUse"] for h in g["hooks"]]
    assert commands == ["my-linter", "amagi-hookguard hook"]


def test_install_twice_does_not_duplicate(tmp_path):
    path = tmp_path / "settings.json"
    settings.install(path, "amagi-hookguard hook")
    settings.install(path, "amagi-hookguard hook")
    data = read(path)
    assert len(data["hooks"]["PreToolUse"]) == 1 and len(data["hooks"]["PostToolUse"]) == 1


def test_install_dry_run_writes_nothing(tmp_path):
    path = tmp_path / "settings.json"
    text, _ = settings.install(path, "amagi-hookguard hook", dry_run=True)
    assert "amagi-hookguard hook" in text and not path.exists()


def test_install_refuses_broken_json(tmp_path):
    path = tmp_path / "settings.json"
    path.write_text("{ broken", encoding="utf-8")
    with pytest.raises(json.JSONDecodeError):
        settings.install(path, "amagi-hookguard hook")
    assert path.read_text(encoding="utf-8") == "{ broken"


def test_uninstall_removes_only_hookguard(tmp_path):
    path = tmp_path / "settings.json"
    path.write_text(json.dumps({"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [
        {"type": "command", "command": "my-linter"}]}]}}), encoding="utf-8")
    settings.install(path, "amagi-hookguard hook")
    removed, backup = settings.uninstall(path)
    assert removed == 2 and backup is not None
    assert read(path) == {"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "my-linter"}]}]}}
    assert settings.uninstall(path) == (0, None)


def test_scope_paths(tmp_path, isolated_home):
    assert settings.scope_path("user", str(tmp_path)) == isolated_home / "settings.json"
    assert settings.scope_path("project", str(tmp_path)) == tmp_path / ".claude" / "settings.json"
    assert settings.scope_path("local", str(tmp_path)) == tmp_path / ".claude" / "settings.local.json"


# ------------------------------------------------------------- doctor

def test_doctor_passes_on_a_good_install(tmp_path):
    path = tmp_path / "settings.json"
    settings.install(path, PY_HOOK)
    sections = doctor.run_doctor(str(tmp_path), [str(path)], execute=True)
    report = doctor.render(sections)
    assert doctor.counts(sections)[doctor.FAIL] == 0, report
    selftests = findings(sections, "selftest", doctor.OK)
    assert len(selftests) == 5, report  # 4 PreToolUse cases + the audit write
    assert report.rstrip().endswith("Result: PASS (0 fail, 0 warn)")


@pytest.mark.parametrize("content,code", [
    ('{"hooks": {"PreToolUse": [ }', "json-invalid"),
    ('{"hooks": {"pretooluse": [{"matcher": "*", "hooks": [{"type": "command", "command": "amagi-hookguard hook"}]}]}}', "event-case"),
    ('{"hooks": {"PreToolUse": [{"matcher": "bash", "hooks": [{"type": "command", "command": "echo hi"}]}]}}', "matcher-case"),
    ('{"hooks": {"PreToolUse": [{"matcher": "Bash(", "hooks": [{"type": "command", "command": "echo hi"}]}]}}', "matcher-regex"),
    ('{"hooks": {"PreToolUse": [{"matcher": "*", "hooks": [{"command": "echo hi"}]}]}}', "hook-type"),
    ('{"hooks": {"PreToolUse": [{"matcher": "*", "hooks": [{"type": "command", "command": ""}]}]}}', "command-empty"),
    ('{"hooks": {"PreToolUse": [{"matcher": "*", "hooks": [{"type": "command", "command": "echo hi", "timeout": "10"}]}]}}', "timeout"),
    ('{"hooks": {"PreToolUse": [{"matcher": "*", "command": "echo hi"}]}}', "hooks-shape"),
    ('{"hooks": {"PreToolUse": [{"matcher": "*", "hooks": [{"type": "command", "command": "no-such-binary-hookguard-test --x"}]}]}}', "command-not-found"),
    ('{"hooks": {"PreToolUse": [{"matcher": "*", "hooks": [{"type": "command", "command": "python3 .claude/hooks/missing.py"}]}]}}', "command-not-found"),
    ('{"disableAllHooks": true}', "hooks-disabled"),
    ('{"model": "opus"}', "pre-missing"),
])
def test_doctor_catches_broken_settings(tmp_path, content, code):
    path = tmp_path / "settings.json"
    path.write_text(content, encoding="utf-8")
    sections = doctor.run_doctor(str(tmp_path), [str(path)], execute=False)
    assert findings(sections, code, doctor.FAIL), doctor.render(sections)
    assert doctor.render(sections).rstrip().split("\n")[-1].startswith("Result: FAIL")


def test_doctor_flags_partial_matchers_and_duplicates(tmp_path):
    a, b = tmp_path / "a.json", tmp_path / "b.json"
    a.write_text(json.dumps({"hooks": {
        "PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": PY_HOOK}]}],
        "PostToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": PY_HOOK}]}],
    }}), encoding="utf-8")
    settings.install(b, PY_HOOK)
    sections = doctor.run_doctor(str(tmp_path), [str(a)], execute=False)
    assert findings(sections, "pre-coverage", doctor.FAIL)
    assert findings(sections, "post-coverage", doctor.WARN)
    sections = doctor.run_doctor(str(tmp_path), [str(a), str(b)], execute=False)
    assert findings(sections, "duplicate", doctor.WARN)


def test_doctor_self_test_catches_a_hook_that_never_blocks(tmp_path):
    path = tmp_path / "settings.json"
    # Wired under a hookguard-looking name, but the command just exits 0.
    fake = f'"{Path(sys.executable).as_posix()}" -c "import sys; sys.stdin.read()" amagi-hookguard'
    settings.install(path, fake)
    sections = doctor.run_doctor(str(tmp_path), [str(path)], execute=True)
    bad = findings(sections, "selftest", doctor.FAIL)
    assert len(bad) >= 3, doctor.render(sections)


def test_doctor_missing_file_and_json_output(tmp_path):
    sections = doctor.run_doctor(str(tmp_path), [str(tmp_path / "nope.json")], execute=False)
    assert findings(sections, "missing", doctor.FAIL)
    data = json.loads(doctor.to_json(sections))
    assert data["result"] == "FAIL" and data["fail"] >= 1


def test_doctor_default_scopes(tmp_path, isolated_home):
    settings.install(isolated_home / "settings.json", PY_HOOK)
    sections = doctor.run_doctor(str(tmp_path), None, execute=False)
    titles = " ".join(s.title for s in sections)
    assert "user" in titles and "project" in titles and "local" in titles
    assert doctor.counts(sections)[doctor.FAIL] == 0, doctor.render(sections)


def test_command_problems_expands_project_dir(tmp_path):
    script = tmp_path / ".claude" / "hooks" / "guard.py"
    script.parent.mkdir(parents=True)
    script.write_text("", encoding="utf-8")
    assert doctor.command_problems(f'"{sys.executable}" "$CLAUDE_PROJECT_DIR/.claude/hooks/guard.py"', str(tmp_path)) == []
    assert doctor.command_problems(f'"{sys.executable}" "$CLAUDE_PROJECT_DIR/.claude/hooks/other.py"', str(tmp_path))
