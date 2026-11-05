"""Honeytokens: unique, traceable bait values and the decoy files that carry them.

Every token embeds a random marker, so seeing that marker anywhere (a file open, a URL, a DNS
name, an HTTP body, a command line) is proof that something read the bait. Nothing here reads a
real credential: the chamber writes these files into a throwaway HOME, and ``plant`` (opt-in)
only writes into well-known paths that do not exist yet.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import string
from pathlib import Path
from typing import Dict, List

_UP = string.ascii_uppercase + string.digits
_B62 = string.ascii_letters + string.digits


def _rand(alphabet: str, n: int) -> str:
    return "".join(secrets.choice(alphabet) for _ in range(n))


def marker() -> str:
    """A short lowercase hex marker that survives URL/DNS encoding (DNS names are case-folded)."""
    return "xr" + secrets.token_hex(5)


def _token_set(mk: str) -> Dict[str, str]:
    """Bait values keyed by kind. Each contains the marker in a form that survives lowercasing."""
    return {
        "openai_key": f"sk-proj-{mk}{_rand(_B62, 30)}",
        "anthropic_key": f"sk-ant-api03-{mk}{_rand(_B62, 40)}",
        "aws_access_key": "AKIA" + _rand(_UP, 16),
        "aws_secret_key": f"{mk}{_rand(_B62, 28)}",
        "github_token": f"ghp_{mk}{_rand(_B62, 24)}",
        "wallet_seed": " ".join([mk] + [secrets.choice(_WORDS) for _ in range(11)]),
        "ssh_key_body": f"{mk}{_rand(_B62, 60)}",
        "memory_canary": f"My bank PIN is {mk[2:8]} and my recovery phrase is in {mk}.txt",
        "telegram_token": f"{secrets.randbelow(10**9)}:{mk}{_rand(_B62, 24)}",
    }


_WORDS = ("abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract",
          "absurd", "abuse", "access", "accident", "account", "accuse", "achieve", "acid")


def _layout(home: Path, hermes_home: Path, t: Dict[str, str]) -> List[dict]:
    """Decoy files: (kind, path, content). Paths are built from parts on purpose: they are the
    places a credential-stealing plugin would look, which is exactly why the bait goes there."""
    ssh_hdr = "-----BEGIN " + "OPENSSH PRIVATE KEY-----"
    ssh_ftr = "-----END " + "OPENSSH PRIVATE KEY-----"
    return [
        {"kind": "hermes_env", "path": hermes_home / ".env",
         "content": f"OPENAI_API_KEY={t['openai_key']}\nANTHROPIC_API_KEY={t['anthropic_key']}\n"
                    f"TELEGRAM_BOT_TOKEN={t['telegram_token']}\n"},
        {"kind": "hermes_auth", "path": hermes_home / "auth.json",
         "content": json.dumps({"providers": {"openrouter": {"api_key": t["openai_key"]}}}, indent=2)},
        {"kind": "aws_credentials", "path": home / ".aws" / "credentials",
         "content": f"[default]\naws_access_key_id = {t['aws_access_key']}\n"
                    f"aws_secret_access_key = {t['aws_secret_key']}\n"},
        {"kind": "ssh_private_key", "path": home / ".ssh" / "id_ed25519",
         "content": f"{ssh_hdr}\n{t['ssh_key_body']}\n{ssh_ftr}\n"},
        {"kind": "git_credentials", "path": home / ".git-credentials",
         "content": f"https://cipo:{t['github_token']}@github.com\n"},
        {"kind": "solana_wallet", "path": home / ".config" / "solana" / "id.json",
         "content": json.dumps([secrets.randbelow(256) for _ in range(64)])},
        {"kind": "wallet_seed", "path": home / "Documents" / "wallet-backup.txt",
         "content": t["wallet_seed"] + "\n"},
        {"kind": "hermes_memory", "path": hermes_home / "memories" / "USER.md",
         "content": f"# User\n- {t['memory_canary']}\n"},
    ]


def bait_env(t: Dict[str, str]) -> Dict[str, str]:
    """Environment variables a plugin under detonation sees (values are bait)."""
    return {
        "OPENAI_API_KEY": t["openai_key"], "ANTHROPIC_API_KEY": t["anthropic_key"],
        "AWS_ACCESS_KEY_ID": t["aws_access_key"], "AWS_SECRET_ACCESS_KEY": t["aws_secret_key"],
        "GITHUB_TOKEN": t["github_token"], "TELEGRAM_BOT_TOKEN": t["telegram_token"],
    }


def build_world(root: Path) -> dict:
    """Create a throwaway HOME + HERMES_HOME seeded with bait under *root*."""
    home = root / "home"
    hermes_home = home / ".hermes"
    for d in (home, hermes_home, hermes_home / "plugins", hermes_home / "plugin-data"):
        d.mkdir(parents=True, exist_ok=True)
    mk = marker()
    tokens = _token_set(mk)
    files = []
    for item in _layout(home, hermes_home, tokens):
        p = Path(item["path"])
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(item["content"], encoding="utf-8")
        files.append({"kind": item["kind"], "path": str(p)})
    (hermes_home / "config.yaml").write_text("model:\n  default: nous/hermes-4\n", encoding="utf-8")
    return {"root": str(root), "home": str(home), "hermes_home": str(hermes_home), "marker": mk,
            "tokens": tokens, "files": files, "env": bait_env(tokens)}


def needles(world: dict) -> List[str]:
    """Strings whose appearance anywhere proves the bait was read: the marker plus every token."""
    vals = {world["marker"]}
    for v in world["tokens"].values():
        vals.add(v)
        # the AWS key id has no marker; it is unique on its own
    return sorted(vals, key=len, reverse=True)


def find_needles(text: str, world_needles: List[str]) -> List[str]:
    if not text:
        return []
    low = text.lower()
    return [n for n in world_needles if n.lower() in low]


# ── live bait (opt-in) ───────────────────────────────────────────────────────

def _live_candidates(home: Path, t: Dict[str, str]) -> List[dict]:
    """Decoys for the real machine. Only ever written where nothing exists yet."""
    out = []
    for item in _layout(home, home / ".xray-decoy-hermes", t):
        if item["kind"] in ("hermes_env", "hermes_auth", "hermes_memory"):
            continue  # never touch the real Hermes home
        out.append(item)
    out.append({"kind": "env_backup", "path": home / ".env.backup",
                "content": f"OPENAI_API_KEY={t['openai_key']}\n"})
    return out


def plant(home: Path, registry_file: Path) -> List[dict]:
    """Write decoys into empty well-known paths; record exactly what was written so ``remove``
    deletes only files X-Ray created (and only if they are unchanged)."""
    state = load_registry(registry_file)
    if state.get("files"):
        return state["files"]
    mk = marker()
    tokens = _token_set(mk)
    planted = []
    for item in _live_candidates(home, tokens):
        p = Path(item["path"])
        if p.exists() or p.is_symlink():
            continue
        p.parent.mkdir(parents=True, exist_ok=True)
        data = item["content"].encode("utf-8")
        p.write_bytes(data)  # bytes, so Windows newline translation can't change the size
        try:
            os.chmod(p, 0o600)
        except OSError:
            pass
        planted.append({"kind": item["kind"], "path": str(p), "size": len(data),
                        "sha256": hashlib.sha256(data).hexdigest()})
    state = {"marker": mk, "tokens": tokens, "files": planted}
    registry_file.write_text(json.dumps(state, indent=2), encoding="utf-8")
    os.chmod(registry_file, 0o600)
    return planted


def remove(registry_file: Path) -> List[str]:
    state = load_registry(registry_file)
    removed = []
    for f in state.get("files", []):
        p = Path(f["path"])
        try:
            if p.is_file() and _unchanged(p, f):
                p.unlink()
                removed.append(str(p))
        except OSError:
            pass
    if registry_file.exists():
        registry_file.unlink()
    return removed


def _unchanged(p: Path, f: dict) -> bool:
    """Only delete a decoy that is still exactly what X-Ray wrote."""
    data = p.read_bytes()
    if f.get("sha256"):
        return hashlib.sha256(data).hexdigest() == f["sha256"]
    # registries from 0.1.0 stored only the size; accept a CRLF-translated copy too
    return len(data) in (f.get("size", -1), f.get("size", -1) + data.count(b"\r\n"))

def load_registry(registry_file: Path) -> dict:
    try:
        return json.loads(registry_file.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
