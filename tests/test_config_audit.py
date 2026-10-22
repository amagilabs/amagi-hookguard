import json

from amagi_hookguard import audit
from amagi_hookguard.config import Config, load_config
from amagi_hookguard.rules import ALLOW, BLOCK, evaluate_command


def write_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data), encoding="utf-8")


def test_defaults_without_files(tmp_path):
    cfg = load_config(str(tmp_path))
    assert cfg.protected_branches == ["main", "master"]
    assert cfg.sources == [] and cfg.notes == []


def test_user_config_is_trusted(isolated_home, tmp_path):
    write_json(isolated_home / "hookguard.json", {
        "disabled_rules": ["sql-drop"],
        "protected_branches": ["prod"],
        "allow_commands": ["^make clean$"],
        "ask_as_block": True,
        "audit_max_bytes": 1234,
        "bogus": 1,
    })
    cfg = load_config(str(tmp_path))
    assert cfg.disabled_rules == ["sql-drop"]
    assert cfg.protected_branches == ["main", "master", "prod"]
    assert cfg.allow_commands == ["^make clean$"]
    assert cfg.ask_as_block is True
    assert cfg.audit_max_bytes == 1234
    assert any("unknown key 'bogus'" in n for n in cfg.notes)


def test_untrusted_project_config_can_only_tighten(tmp_path):
    project = tmp_path / "proj"
    write_json(project / ".claude" / "hookguard.json", {
        "disabled_rules": ["rm-critical-path"],
        "allow_commands": [".*"],
        "protected_branches": ["release/*"],
        "secret_globs": ["*.secret"],
        "fail_closed": True,
    })
    cfg = load_config(str(project))
    assert cfg.disabled_rules == []
    assert cfg.allow_commands == []
    assert "release/*" in cfg.protected_branches
    assert cfg.secret_globs == ["*.secret"]
    assert cfg.fail_closed is True
    assert sum("ignored" in n for n in cfg.notes) == 2
    # The repo cannot switch the guard off for itself.
    assert evaluate_command("rm -rf ~", str(project), cfg).action == BLOCK


def test_untrusted_project_cannot_loosen_booleans(isolated_home, tmp_path):
    write_json(isolated_home / "hookguard.json", {"ask_as_block": True})
    project = tmp_path / "proj"
    write_json(project / ".claude" / "hookguard.json", {"ask_as_block": False})
    assert load_config(str(project)).ask_as_block is True


def test_trusted_project_config(isolated_home, tmp_path):
    write_json(isolated_home / "hookguard.json", {"trust_project_config": True})
    project = tmp_path / "proj"
    write_json(project / ".claude" / "hookguard.json", {"disabled_rules": ["git-reset-hard"]})
    cfg = load_config(str(project))
    assert cfg.disabled_rules == ["git-reset-hard"]
    assert evaluate_command("git reset --hard", str(project), cfg).action == ALLOW


def test_broken_config_is_reported_not_fatal(isolated_home, tmp_path):
    (isolated_home / "hookguard.json").write_text("{ nope", encoding="utf-8")
    cfg = load_config(str(tmp_path))
    assert cfg.protected_branches == ["main", "master"]
    assert any("could not read" in n for n in cfg.notes)


# ------------------------------------------------------------------ audit

def fake(prefix, n=36):
    # Built at runtime so the repo never contains a token-shaped string.
    return prefix + "A1b2" * (n // 4)


def test_redact_common_secrets():
    samples = [
        fake("sk-"),
        fake("gh" + "p_"),
        fake("github_" + "pat_"),
        fake("xox" + "b-"),
        "AKIA" + "ABCDEFGHIJKLMNOP",
        fake("AI" + "za", 36),
        fake("pypi" + "-"),
    ]
    for s in samples:
        out = audit.redact(f"curl -H 'x: {s}' https://x")
        assert s not in out and "[REDACTED]" in out, s
    assert "hunter2" not in audit.redact("mysql --password=hunter2 db")
    assert "hunter2" not in audit.redact('API_KEY="hunter2" ./run')
    assert "hunter2" not in audit.redact("git clone https://bob:hunter2@example.com/r.git")
    out = audit.redact("Authorization: Bearer " + fake("", 24))
    assert "Bearer [REDACTED]" in out
    pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY-----"
    assert audit.redact(pem) == "[REDACTED PRIVATE KEY]"
    assert audit.redact("ls -la") == "ls -la"


def test_summarize_input_picks_the_useful_field():
    assert audit.summarize_input("Bash", {"command": "ls", "description": "list"}) == "ls"
    assert audit.summarize_input("Read", {"file_path": "/a/b.py"}) == "/a/b.py"
    assert audit.summarize_input("Grep", {"pattern": "TODO", "path": "src"}) == "TODO in src"
    long = audit.summarize_input("Bash", {"command": "x" * 1000})
    assert len(long) < 450 and long.endswith("chars]")
    assert audit.summarize_input("Bash", None) == ""


def test_write_read_and_rotate(audit_file):
    cfg = Config()
    cfg.audit_max_bytes = 200
    for i in range(10):
        audit.write({"i": i, "pad": "x" * 50}, cfg)
    rotated = audit_file.with_name(audit_file.name + ".1")
    assert rotated.exists()
    current = [r["i"] for r in audit.read(audit_file)]
    assert current and current[-1] == 9
    assert audit_file.stat().st_size < 400


def test_read_skips_garbage(audit_file):
    audit_file.write_text('{"a": 1}\nnot json\n\n[1,2]\n{"b": 2}\n', encoding="utf-8")
    assert list(audit.read(audit_file)) == [{"a": 1}, {"b": 2}]


def test_audit_path_precedence(monkeypatch, tmp_path, isolated_home):
    cfg = Config()
    cfg.audit_log = str(tmp_path / "cfg.jsonl")
    assert audit.audit_path(cfg) == tmp_path / "audit.jsonl"  # env var wins
    monkeypatch.delenv(audit.ENV_VAR)
    assert audit.audit_path(cfg) == tmp_path / "cfg.jsonl"
    assert audit.audit_path(Config()) == isolated_home / "hookguard" / "audit.jsonl"


def test_response_helpers_and_format():
    assert audit.response_ok({"stdout": "x"}) is True
    assert audit.response_ok({"interrupted": True}) is False
    assert audit.response_ok({"success": False}) is False
    assert audit.response_ok("text") is None
    assert audit.response_size({"a": 1}) == len('{"a": 1}')
    line = audit.format_record({"ts": "T", "event": "PreToolUse", "decision": "block", "tool": "Bash",
                                "input": "rm -rf ~", "rule": "rm-critical-path"})
    assert "BLOCK" in line and "[rm-critical-path]" in line
    assert audit.tail([1, 2, 3], 2) == [2, 3] and audit.tail([1, 2], 0) == [1, 2]
