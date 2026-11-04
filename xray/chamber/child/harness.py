"""Detonation child entry point: ``python harness.py <config.json>``.

``sitecustomize`` (same directory, first on PYTHONPATH) has already installed the audit hook and
the clock warp. This module loads the plugin under test with a recording ``ctx`` that mirrors the
public PluginContext registration surface, then exercises everything it registered: each tool is
called with schema-derived fuzz inputs, each hook is fired with synthetic arguments, each slash
command is invoked. No Hermes internals are imported.
"""

import asyncio
import importlib.util
import inspect
import json
import os
import sys
import threading
import time
import traceback

import sitecustomize as sc  # noqa: E402  (our own, installed by PYTHONPATH)

from fuzz import fuzz_args, synthetic_hook_kwargs  # noqa: E402

CFG = json.load(open(sys.argv[1], encoding="utf-8"))
TARGET = CFG["target_module"]
PER_CALL = float(CFG.get("per_call_timeout", 4.0))
REC = {"tools": [], "hooks": [], "commands": [], "cli_commands": [], "middleware": [],
       "skills": [], "errors": [], "calls": 0}
_tools, _hooks, _commands = {}, {}, {}


def _meta(**kw):
    sc._emit(dict({"kind": "meta", "t": time.time()}, **kw))


class _Reg:
    def __init__(self, kind, name):
        self.kind, self.name = kind, name

    def unregister(self):
        return None


class FakeCtx:
    """Records registrations. Names the real PluginContext lacks raise AttributeError."""
    plugin_config = {}
    profile_name = "default"

    def __init__(self, plugin_id):
        self.plugin_id = plugin_id

    def register_tool(self, name, toolset="", schema=None, handler=None, *a, **kw):
        if handler is None and a:
            handler = a[0]
        schema = schema or kw.get("schema") or {}
        handler = handler or kw.get("handler")
        _tools[str(name)] = (schema, handler, bool(kw.get("is_async")))
        REC["tools"].append(str(name))
        return _Reg("tool", name)

    def register_hook(self, hook_name, callback, *, hold_stream=False):
        _hooks.setdefault(str(hook_name), []).append(callback)
        REC["hooks"].append(str(hook_name))
        return _Reg("hook", hook_name)

    def register_middleware(self, kind, callback):
        REC["middleware"].append(str(kind))
        return _Reg("middleware", kind)

    def register_command(self, name, handler=None, *a, **kw):
        _commands[str(name)] = handler
        REC["commands"].append(str(name))
        return _Reg("command", name)

    def register_cli_command(self, name, *a, **kw):
        REC["cli_commands"].append(str(name))
        return _Reg("cli", name)

    def register_skill(self, name, *a, **kw):
        REC["skills"].append(str(name))

    def get_config(self, key, default=None):
        return default

    def set_config(self, key, value):
        return None

    def has_plugin(self, plugin_id):
        return False

    def has_capability(self, name):
        return False

    def on_unload(self, cb):
        return _Reg("unload", "")

    def session_cwd(self):
        return os.getcwd()

    def dispatch_tool(self, tool_name, args, **kw):
        return json.dumps({"ok": True, "result": "xray-chamber"})

    def __getattr__(self, name):
        if name.startswith("register_") or name in ("emit", "subscribe", "inject_message",
                                                       "post_message", "spawn_task"):
            def _noop(*a, **kw):
                return None
            return _noop
        raise AttributeError(name)


def _run_with_timeout(fn, *a, **kw):
    box = {}

    def target():
        try:
            out = fn(*a, **kw)
            if inspect.isawaitable(out):
                out = asyncio.run(_await(out))
            box["out"] = out
        except BaseException as exc:  # the plugin's failure is data, not ours
            box["err"] = "%s: %s" % (type(exc).__name__, exc)

    th = threading.Thread(target=target, daemon=True)
    th.start()
    th.join(PER_CALL)
    if th.is_alive():
        return None, "timeout"
    return box.get("out"), box.get("err")


async def _await(aw):
    return await aw


def main():
    plugin_dir = CFG["plugin_dir"]
    sc.set_phase("import")
    spec = importlib.util.spec_from_file_location(
        TARGET, os.path.join(plugin_dir, "__init__.py"), submodule_search_locations=[plugin_dir])
    mod = importlib.util.module_from_spec(spec)
    sys.modules[TARGET] = mod
    try:
        spec.loader.exec_module(mod)
    except BaseException as exc:
        REC["errors"].append("import: %s: %s" % (type(exc).__name__, exc))
        _meta(event="xray.result", result=REC)
        return

    sc.set_phase("register")
    reg = getattr(mod, "register", None)
    if callable(reg):
        _, err = _run_with_timeout(reg, FakeCtx(CFG.get("plugin_id", "target")))
        if err:
            REC["errors"].append("register: " + err)

    sc.warp_now()
    sc._emit({"event": "xray.warp", "kind": "meta", "t": time.time(), "warp_days": sc._WARP_DAYS})
    rounds = int(CFG.get("fuzz_rounds", 3))
    for name, (schema, handler, is_async) in list(_tools.items()):
        if not callable(handler):
            continue
        for i, args in enumerate(fuzz_args(schema, rounds)):
            sc.set_phase("tool:" + name)
            _, err = _run_with_timeout(handler, args, task_id="xray-%d" % i)
            REC["calls"] += 1
            if err:
                REC["errors"].append("tool %s: %s" % (name, err[:200]))

    for hook, cbs in list(_hooks.items()):
        for cb in cbs:
            sc.set_phase("hook:" + hook)
            _, err = _run_with_timeout(cb, **synthetic_hook_kwargs(hook))
            REC["calls"] += 1
            if err:
                REC["errors"].append("hook %s: %s" % (hook, err[:200]))

    for name, handler in list(_commands.items()):
        if not callable(handler):
            continue
        for raw in ("", "status", "--help"):
            sc.set_phase("command:" + name)
            _run_with_timeout(handler, raw)
            REC["calls"] += 1

    sc.set_phase("background")
    time.sleep(float(CFG.get("linger", 1.5)))  # let threads a plugin started at register() run
    _meta(event="xray.result", result=REC)


if __name__ == "__main__":
    try:
        main()
    except BaseException:
        _meta(event="xray.crash", error=traceback.format_exc()[-800:])
    sys.stdout.flush()
    os._exit(0)
