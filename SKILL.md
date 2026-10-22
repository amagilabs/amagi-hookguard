---
name: amagi-hookguard
description: The amagi-hookguard CLI installs tested Claude Code PreToolUse and PostToolUse hooks that block destructive shell commands (rm -rf ~, disk wipes, recursive chmod of /), reads of secret files (.env, SSH keys, cloud credentials) and git force pushes to main, ask before git reset --hard or curl | sh, and log every tool call to a local JSONL audit file. Its doctor command checks settings.json hook wiring for broken JSON, wrong-case event names and matchers, missing scripts and bad timeouts. Use when the user wants guardrails for Claude Code, asks why a hook isn't firing, wants to test whether a command would be blocked, or wants to see what Claude ran.
---

# amagi-hookguard

## When to use

- The user wants Claude Code to stop before running something destructive, reading a
  `.env` or SSH key, or force-pushing to `main`.
- A hook in `settings.json` isn't firing and they want to know why. `doctor` checks
  every settings file Claude Code reads.
- They want to know whether a specific command would be blocked, without running it.
- They want a record of what Claude ran in a session.

It needs no API keys and makes no network calls.

## How to invoke

```
amagi-hookguard install [--scope user|project|local] [--settings PATH] [--absolute] [--dry-run]
amagi-hookguard doctor [--settings PATH ...] [--project DIR] [--no-exec] [--json]
amagi-hookguard check "COMMAND" | --read PATH | --tool NAME --input JSON
amagi-hookguard rules
amagi-hookguard log [-n N] [--blocked] [--session ID] [--json] [--path]
amagi-hookguard uninstall [--scope ...] [--settings PATH]
```

Examples:

```
amagi-hookguard install                     # wires ~/.claude/settings.json, backs it up first
amagi-hookguard doctor                      # checks user, project, local and managed settings
amagi-hookguard check "git push -f origin main"
amagi-hookguard check --read ~/.aws/credentials
amagi-hookguard log --blocked
```

Claude Code runs `amagi-hookguard hook` itself, once per tool call, with the event as JSON
on stdin. You don't call `hook` by hand.

## What to read afterward

- `check` prints `BLOCK`, `ASK` or `allow`, plus the rule id and reason. Exit codes are
  2 for block, 3 for ask and 0 for allow.
- `doctor` prints one section per settings file, then the hookguard wiring, a self-test
  that pipes sample events through the wired command, and the audit log status. It ends
  with `Result: PASS` or `Result: FAIL (n fail, n warn)` and exits 1 on any FAIL.
- `log` prints one line per call: time, PRE/POST, decision, tool, and the command or path
  with secrets redacted.

## Notes

- Block means the hook exits 2 and Claude sees the reason. Ask means Claude Code shows
  the user a permission prompt.
- Config lives in `~/.claude/hookguard.json`, with `disabled_rules`, `protected_branches`,
  `secret_globs`, `secret_allow_globs`, `allow_commands`, `ask_as_block` and
  `fail_closed`. A project's `.claude/hookguard.json` can only add protection unless the
  user config sets `"trust_project_config": true`.
- The audit log is `~/.claude/hookguard/audit.jsonl`. It rotates at 10 MB.
- This is pattern matching on the command text, not a sandbox. A determined script can
  get around it. Treat it as a seatbelt, not a jail.
