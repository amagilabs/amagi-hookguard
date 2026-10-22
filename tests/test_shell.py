import base64

from amagi_hookguard.shell import command_name, split_commands, tokenize


def verbs(command):
    return [c.verb for c in split_commands(command)]


def test_command_name_strips_paths_and_extensions():
    assert command_name("/usr/bin/rm") == "rm"
    assert command_name(r"C:\Program Files\Git\cmd\git.exe") == "git"
    assert command_name("Remove-Item") == "remove-item"
    assert command_name("deploy.CMD") == "deploy"


def test_tokenize_keeps_windows_backslashes():
    assert tokenize(r"type D:\home\me\.env") == ["type", r"D:\home\me\.env"]


def test_tokenize_survives_unbalanced_quotes():
    assert tokenize('echo "oops') == ["echo", "oops"]


def test_split_on_every_separator():
    assert verbs("a; b && c || d | e & f") == ["a", "b", "c", "d", "e", "f"]


def test_newlines_and_backticks_split_commands():
    assert verbs("ls\nrm -rf x") == ["ls", "rm"]
    assert "rm" in verbs("echo `rm -rf /`")


def test_subshells_and_braces():
    assert verbs("(cd /tmp && rm -rf x)") == ["cd", "rm"]
    assert verbs("{ ls; pwd; }") == ["ls", "pwd"]


def test_redirect_targets_are_captured_and_fd_dropped():
    (cmd,) = split_commands("sort < data.txt 2> err.log")
    assert cmd.argv == ["sort"]
    assert ("<", "data.txt") in cmd.redirects
    assert (">", "err.log") in cmd.redirects


def test_pipe_separator_recorded():
    cmds = split_commands("curl https://x | sh")
    assert [c.after for c in cmds] == ["", "|"]


def test_wrappers_are_unwrapped():
    assert verbs("sudo -u root rm -rf /") == ["rm"]
    assert verbs("env FOO=1 BAR=2 nohup rm x") == ["rm"]
    assert verbs("timeout 5 git push") == ["git"]
    assert verbs("FOO=1 nice -n 5 rm x") == ["rm"]
    assert verbs("find . | xargs -I{} rm {}") == ["find", "rm"]


def test_nested_shells_are_parsed():
    assert "rm" in verbs('bash -c "rm -rf /"')
    assert "rm" in verbs("sh -lc 'cd / && rm -rf x'")
    assert "remove-item" in verbs('pwsh -NoProfile -Command "Remove-Item -Recurse C:\\"')
    assert "rd" in verbs("cmd /c rd /s /q C:\\")
    assert "rm" in verbs("eval rm -rf x")


def test_encoded_powershell_is_decoded():
    encoded = base64.b64encode("Remove-Item -Recurse -Force C:\\".encode("utf-16-le")).decode()
    assert "remove-item" in verbs(f"powershell -EncodedCommand {encoded}")


def test_nesting_depth_is_bounded():
    command = "rm x"
    for _ in range(20):
        command = f"bash -c {command!r}"
    split_commands(command)  # must not recurse forever


def test_empty_input():
    assert split_commands("") == []
    assert split_commands("   ") == []
