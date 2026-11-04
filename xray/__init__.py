"""Plugin X-Ray: trap-based plugin security for Hermes.

`register(ctx)` wires:
  • `hermes xray …` CLI (detonate, verdicts, show, bait, diff, disclose, alerts)
  • an on_session_start hook that arms the runtime bait tracer
  • a pre_tool_call hook that (only when `enforce` is on) escalates a flagged plugin's tool calls
    to Hermes' own human-approval gate

Nothing here patches Hermes core. The sandbox, clock warp and egress blocking all live in a
throwaway child process (see chamber/). Stdlib only; no LLM calls.
"""

from __future__ import annotations

import os
from pathlib import Path

from . import bait, store
from .tracer import RuntimeTracer

_TRACER = None
_PLUGIN_ID = "xray"


def _bait_registry() -> Path:
    return store.data_dir() / "live-bait.json"


def _arm_runtime_tracer(ctx=None):
    global _TRACER
    if _TRACER is not None:
        return _TRACER
    reg = bait.load_registry(_bait_registry())
    if not reg.get("files"):
        return None  # no bait planted; nothing to watch
    decoys = {f["path"]: f["kind"] for f in reg["files"]}
    needles = [reg["marker"]] + list(reg.get("tokens", {}).values())

    def _on_alert(a: dict):
        try:
            store.add_alert(a["plugin"], a["severity"], a["kind"], a["detail"], a.get("location", ""))
        except Exception:
            pass

    t = RuntimeTracer(needles, decoys, _on_alert)
    t.install()
    _TRACER = t
    return t


def _setting(key: str, default):
    """Read plugins.entries.xray.settings.<key> (public hermes_cli.config reader)."""
    try:
        from hermes_cli.config import load_config_readonly
        settings = (((load_config_readonly() or {}).get("plugins", {}) or {}).get("entries", {})
                    or {}).get(_PLUGIN_ID, {}) or {}
        settings = settings.get("settings", {}) or {}
        return settings.get(key, default)
    except Exception:
        return default


def _on_session_start(**kwargs):
    if _setting("bait_runtime", True):
        _arm_runtime_tracer()
    return None


def _flagged_plugins() -> set:
    try:
        return {name for name, d in store.latest_verdicts().items() if d["verdict"] == "RED"}
    except Exception:
        return set()


def _pre_tool_call(tool_name=None, args=None, task_id=None, **kwargs):
    """When enforce is on, a tool owned by a RED plugin is escalated to human approval.

    Ownership comes from the public tool registry: the handler's module lives under
    ``hermes_plugins.<slug>`` for a directory plugin. Core tools are never escalated.
    """
    enforce = _setting("enforce", False) or os.environ.get("XRAY_ENFORCE") == "1"
    if not enforce or not tool_name:
        return None
    flagged = _flagged_plugins()
    if not flagged:
        return None
    owner = None
    try:
        from tools.registry import registry
        entry = registry.get_entry(tool_name)
        module = getattr(getattr(entry, "handler", None), "__module__", "") or ""
    except Exception:
        module = ""
    if module.startswith("hermes_plugins."):
        slug = module.split(".")[1].split("__home_")[0]
        for name in flagged:
            if name.replace("-", "_").replace("/", "__") == slug:
                owner = name
                break
    if owner:
        return {"action": "approve",
                "message": f"Plugin X-Ray flagged '{owner}' RED in detonation. Approve this "
                           f"'{tool_name}' call?"}
    return None


def _slash(raw_args: str = "", **kwargs):
    from .cli import summary_text
    return summary_text()


def register(ctx):
    from .cli import setup_argparse, dispatch
    ctx.register_hook("on_session_start", _on_session_start)
    ctx.register_command("xray", _slash, description="Plugin X-Ray: verdicts and bait alerts")
    ctx.register_hook("pre_tool_call", _pre_tool_call)
    try:
        ctx.register_cli_command(name="xray", help="Detonate and audit Hermes plugins",
                                 setup_fn=setup_argparse, handler_fn=dispatch)
    except Exception:
        pass
