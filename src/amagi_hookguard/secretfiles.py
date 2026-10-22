"""Which file paths count as secrets."""

from __future__ import annotations

import fnmatch
from typing import Iterable, List, Optional

# Patterns without a "/" match the file name; patterns with one match the end of the path.
DEFAULT_SECRET_GLOBS = [
    ".env",
    ".env.*",
    "*.env",
    ".envrc",
    "*.pem",
    "*.key",
    "*.p12",
    "*.pfx",
    "*.jks",
    "*.keystore",
    "*.kdbx",
    "id_rsa",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "id_rsa_*",
    "id_ed25519_*",
    ".netrc",
    "_netrc",
    ".pgpass",
    ".git-credentials",
    ".npmrc",
    ".pypirc",
    ".htpasswd",
    ".dockercfg",
    "credentials.json",
    "client_secret*.json",
    "service-account*.json",
    "application_default_credentials.json",
    "secrets.json",
    "secrets.yml",
    "secrets.yaml",
    "terraform.tfvars",
    "*.auto.tfvars",
    ".aws/credentials",
    ".docker/config.json",
    ".kube/config",
    ".config/gh/hosts.yml",
    ".ssh/*",
    ".gnupg/*",
]

DEFAULT_ALLOW_GLOBS = [
    ".env.example",
    ".env.sample",
    ".env.template",
    ".env.dist",
    ".env.defaults",
    "*.pub",
    ".ssh/known_hosts",
    ".ssh/config",
]


def normalize(path: str) -> str:
    p = path.strip().strip("\"'").replace("\\", "/")
    while "//" in p:
        p = p.replace("//", "/")
    return p.rstrip("/")


def _matches(path: str, pattern: str) -> bool:
    pattern = pattern.replace("\\", "/").lower()
    low = path.lower()
    if "/" in pattern:
        pattern = pattern.lstrip("/")
        return fnmatch.fnmatchcase(low, pattern) or fnmatch.fnmatchcase(low, "*/" + pattern)
    return fnmatch.fnmatchcase(low.rsplit("/", 1)[-1], pattern)


def secret_match(
    path: str,
    extra: Iterable[str] = (),
    allow: Iterable[str] = (),
) -> Optional[str]:
    """Return the glob that marks `path` as a secret, or None."""
    if not path or not isinstance(path, str):
        return None
    p = normalize(path)
    if not p:
        return None
    for pattern in list(DEFAULT_ALLOW_GLOBS) + list(allow):
        if _matches(p, pattern):
            return None
    patterns: List[str] = list(DEFAULT_SECRET_GLOBS) + list(extra)
    for pattern in patterns:
        if _matches(p, pattern):
            return pattern
    return None
