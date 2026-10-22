import pytest

from amagi_hookguard.secretfiles import secret_match


@pytest.mark.parametrize("path", [
    ".env", "app/.env", ".env.production", "config/prod.env", ".envrc",
    "certs/server.pem", "tls.key", "store.p12", "~/.ssh/id_rsa", "/home/u/.ssh/id_ed25519",
    r"D:\home\me\.ssh\id_ecdsa", "~/.aws/credentials", "~/.netrc", ".git-credentials",
    ".npmrc", ".pypirc", "credentials.json", "client_secret_123.json", "terraform.tfvars",
    "~/.docker/config.json", "~/.kube/config", "secrets.yaml", "vault.kdbx", "ENV/.ENV",
])
def test_secret_paths_match(path):
    assert secret_match(path, [], []) is not None


@pytest.mark.parametrize("path", [
    ".env.example", ".env.sample", "app/.env.template", "~/.ssh/id_ed25519.pub", "~/.ssh/known_hosts",
    "~/.ssh/config", "README.md", "src/environment.py", "keys.py", "docs/env.md", "monkey.txt",
    "config.json", "",
])
def test_ordinary_paths_do_not_match(path):
    assert secret_match(path, [], []) is None


def test_extra_and_allow_globs():
    assert secret_match("deploy/token.txt", ["token.txt"], []) == "token.txt"
    assert secret_match("fixtures/test.pem", [], ["fixtures/*.pem"]) is None
    assert secret_match("certs/test.pem", [], ["fixtures/*.pem"]) is not None
