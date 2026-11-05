"""The Detonation Chamber: run a plugin in a throwaway world full of bait, at three clock
offsets, and collect what it did. Returns raw runs; ``xray.analysis`` turns them into a verdict.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import List, Optional

from .. import bait

CHILD_DIR = Path(__file__).resolve().parent / "child"
DEFAULT_WARPS = (0, 30, 90)

# Environment the child inherits from us. Everything else (real keys, tokens, proxies) is dropped.
_PASS_ENV = ("PATH", "LANG", "LC_ALL", "TZ", "SYSTEMROOT", "TMPDIR", "TEMP", "TMP")


def _child_env(world: dict, events: Path, warp: int, allow_exec: bool) -> dict:
    env = {k: os.environ[k] for k in _PASS_ENV if k in os.environ}
    env.update(world["env"])  # bait credentials, not real ones
    env.update({
        "HOME": world["home"], "USERPROFILE": world["home"], "HERMES_HOME": world["hermes_home"],
        "PYTHONPATH": str(CHILD_DIR), "PYTHONDONTWRITEBYTECODE": "1", "PYTHONNOUSERSITE": "1",
        "XRAY_EVENTS": str(events), "XRAY_WARP_DAYS": str(warp),
        "XRAY_NEEDLES": "\x1f".join(bait.needles(world)), "XRAY_TARGET_MODULE": "xray_target",
        "XRAY_ALLOW_EXEC": "1" if allow_exec else "0",
        "NO_PROXY": "*", "no_proxy": "*",
    })
    return env


def _read_events(path: Path) -> List[dict]:
    out = []
    try:
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                out.append(json.loads(line))
            except ValueError:
                continue
    except OSError:
        pass
    return out


def stage_copy(plugin_dir: Path, world: dict) -> Path:
    """Copy the plugin into the fake HERMES_HOME/plugins so it runs from a disposable tree."""
    dest = Path(world["hermes_home"]) / "plugins" / plugin_dir.name
    shutil.copytree(plugin_dir, dest, ignore=shutil.ignore_patterns(".git", "__pycache__",
                                                                   "node_modules", ".venv"))
    return dest


_BINARY_EXT = (".so", ".pyd", ".dll", ".dylib", ".exe", ".node", ".bin")
_ELF_PE_MACHO = (b"\x7fELF", b"MZ", b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xca\xfe\xba\xbe")


def native_binaries(plugin_dir: Path, limit: int = 20) -> list:
    """Compiled files shipped in the plugin: their code runs below Python, so it can't be traced."""
    found = []
    plugin_dir = Path(plugin_dir)
    for p in sorted(plugin_dir.rglob("*")):
        if len(found) >= limit:
            break
        if not p.is_file() or ".git" in p.parts or "__pycache__" in p.parts:
            continue
        rel = p.relative_to(plugin_dir).as_posix()
        if p.suffix.lower() in _BINARY_EXT or ".so." in p.name:
            found.append(rel)
            continue
        try:
            with open(p, "rb") as fh:
                head = fh.read(4)
        except OSError:
            continue
        if head.startswith(_ELF_PE_MACHO):
            found.append(rel)
    return found


def detonate(plugin_dir: Path, *, warps=DEFAULT_WARPS, allow_exec: bool = False,
             fuzz_rounds: int = 3, per_call_timeout: float = 4.0, run_timeout: float = 60.0,
             keep: bool = False, python: Optional[str] = None) -> dict:
    plugin_dir = Path(plugin_dir).resolve()
    root = Path(tempfile.mkdtemp(prefix="xray-chamber-"))
    world = bait.build_world(root)
    staged = stage_copy(plugin_dir, world)
    runs = []
    try:
        for warp in warps:
            events = root / f"events-{warp}.jsonl"
            cfg = root / f"cfg-{warp}.json"
            cfg.write_text(json.dumps({
                "plugin_dir": str(staged), "plugin_id": plugin_dir.name,
                "target_module": "xray_target", "fuzz_rounds": fuzz_rounds,
                "per_call_timeout": per_call_timeout,
            }), encoding="utf-8")
            started = time.time()
            timed_out = False
            try:
                proc = subprocess.run(
                    [python or sys.executable, str(CHILD_DIR / "harness.py"), str(cfg)],
                    cwd=str(staged), env=_child_env(world, events, warp, allow_exec),
                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    timeout=run_timeout)
                stderr = proc.stderr.decode("utf-8", "replace")[-2000:]
            except subprocess.TimeoutExpired:
                timed_out, stderr = True, ""
            evs = _read_events(events)
            result = next((e.get("result") for e in evs if e.get("event") == "xray.result"), None)
            crash = next((e.get("error") for e in evs if e.get("event") == "xray.crash"), None)
            runs.append({"warp_days": warp, "events": [e for e in evs if e.get("kind") != "meta"],
                         "registered": result, "crash": crash, "stderr": stderr,
                         "timed_out": timed_out, "seconds": round(time.time() - started, 2)})
    finally:
        if not keep:
            shutil.rmtree(root, ignore_errors=True)
    return {"plugin_dir": str(plugin_dir), "staged_dir": str(staged),
            "binaries": native_binaries(plugin_dir), "world": {
        k: world[k] for k in ("home", "hermes_home", "marker", "files")} | {
        "token_kinds": {v: k for k, v in world["tokens"].items()}},
        "needles": bait.needles(world), "runs": runs, "chamber_root": str(root)}
