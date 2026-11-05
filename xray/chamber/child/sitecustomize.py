"""Loaded first in the detonation child (via PYTHONPATH). Installs the audit hook that records
every interesting event, blocks real network egress, and optionally warps the clock. Writes one
JSON line per event to the file named by ``XRAY_EVENTS``.

This file only ever runs inside X-Ray's own throwaway child process. It never touches the Hermes
process, so it does not patch or override Hermes core.
"""

import builtins
import datetime as _dt
import json
import os
import sys
import time as _time

_EVENTS_PATH = os.environ.get("XRAY_EVENTS")
_WARP_DAYS = int(os.environ.get("XRAY_WARP_DAYS", "0") or "0")
_NEEDLES = [n for n in (os.environ.get("XRAY_NEEDLES", "").split("\x1f")) if n]
_NEEDLES_LC = [n.lower() for n in _NEEDLES]

# audit events we care about -> a normalized record
_WATCH = {
    "open": "open", "os.mkdir": "write", "os.rmdir": "delete", "os.remove": "delete",
    "os.rename": "write", "os.scandir": "listdir", "os.listdir": "listdir",
    "socket.connect": "connect", "socket.getaddrinfo": "dns", "socket.gethostbyname": "dns",
    "urllib.Request": "http", "http.client.connect": "connect", "subprocess.Popen": "subprocess",
    "os.system": "subprocess", "os.exec": "subprocess", "os.posix_spawn": "subprocess",
    "os.fork": "subprocess", "os.forkpty": "subprocess", "_winapi.CreateProcess": "subprocess",
    "os.startfile": "subprocess", "xray.fork_exec": "subprocess",
    "ctypes.dlopen": "native", "shutil.rmtree": "delete", "exec": "dynamic_code",
    "import": "import",
}
_IMPORTS_OF_INTEREST = {"socket", "ctypes", "cffi", "_cffi_backend", "subprocess", "requests", "httpx",
                        "urllib.request", "http.client", "smtplib", "ftplib", "paramiko",
                        "_posixsubprocess", "_winapi", "pty"}

_CHAMBER = os.environ.get("XRAY_CHAMBER_ROOT", "")
_REAL_ROOTS = [r for r in (os.environ.get("XRAY_REAL_HERMES_HOME", ""),
                           os.environ.get("XRAY_REAL_HOME", "")) if r]
# interpreter and Hermes code trees: reading them is how Python runs, not snooping
_CODE_ROOTS = [c for c in os.environ.get("XRAY_CODE_ROOTS", "").split(os.pathsep) if c]
# credential stores in the user's real home; any read of one from the chamber is refused
_CRED_PARTS = ("/.ssh/", "/.aws/", "/.git-credentials", "/.netrc", "/solana/", "wallet",
               "credentials", "/.env", "auth.json", "/memories/", "/.config/gh/", "/.docker/config",
               "/.kube/config", "/.gnupg/", "/.npmrc", "/.pypirc")


def _n(path):
    try:
        return os.path.normcase(os.path.realpath(path)).replace("\\", "/")
    except Exception:
        return str(path).replace("\\", "/")


def _under(p, root):
    r = _n(root).rstrip("/")
    return bool(r) and (p == r or p.startswith(r + "/"))


def _outside_class(path):
    """'' inside the chamber; 'real-credential' for a credential store under the real home;
    'real-home' for other files under the real home; 'outside' for anything else."""
    if not path or not isinstance(path, (str, bytes)) or not _CHAMBER:
        return ""
    if isinstance(path, bytes):
        path = path.decode("utf-8", "replace")
    p = _n(path)
    if _under(p, _CHAMBER) or any(_under(p, c) for c in _CODE_ROOTS):
        return ""
    for root in _REAL_ROOTS:
        if _under(p, root):
            low = p.lower() + ("/" if os.path.isdir(p) else "")
            if any(c in low for c in _CRED_PARTS):
                return "real-credential"
            return "real-home"
    return "outside"


import threading as _threading

_TLS = _threading.local()
_FH = None
_TARGET_PREFIX = os.environ.get("XRAY_TARGET_MODULE", "xray_target")


def _emit(rec):
    global _FH
    if not _EVENTS_PATH:
        return
    try:
        if _FH is None:
            _TLS.busy = True
            try:
                _FH = open(_EVENTS_PATH, "a", encoding="utf-8", buffering=1)
            finally:
                _TLS.busy = False
        _FH.write(json.dumps(rec) + "\n")
    except Exception:
        pass


_HERMES_TOP = ("hermes_cli", "agent", "tools", "gateway", "hermes_constants", "hermes_state",
               "providers", "plugins", "pm", "utils", "cron", "hermes_platform", "cli")


def _via():
    """Who performed the action: the nearest non-stdlib frame. 'hermes' when it is Hermes' own
    code (e.g. a plugin asked agent.secret_scope / credential_pool for its key, which is the
    sanctioned path), 'plugin' when it is the plugin's code, else 'library'."""
    try:
        f = sys._getframe(2)
    except ValueError:
        return "library"
    depth = 0
    while f is not None and depth < 60:
        name = (f.f_globals.get("__name__", "") or "")
        fn = f.f_code.co_filename or ""
        if name == _TARGET_PREFIX or name.startswith(_TARGET_PREFIX + "."):
            return "plugin"
        top = name.split(".", 1)[0]
        if top in _HERMES_TOP:
            return "hermes:" + name
        if not (fn.startswith("<") or fn.startswith(_LIB_ROOTS)):
            return "library:" + name
        f = f.f_back
        depth += 1
    return "library"


def _plugin_called_directly():
    """True when the nearest frame outside the import machinery and ctypes/cffi is the plugin's."""
    try:
        f = sys._getframe(2)
    except ValueError:
        return False
    while f is not None:
        fn = f.f_code.co_filename or ""
        name = f.f_globals.get("__name__", "") or ""
        if fn.startswith("<frozen") or name.split(".")[0] in ("importlib", "ctypes", "cffi"):
            f = f.f_back
            continue
        return name == _TARGET_PREFIX or name.startswith(_TARGET_PREFIX + ".")
    return False


def _origin():
    """'plugin' when a frame of the plugin under test is on the stack; returns (origin, file:line)."""
    try:
        f = sys._getframe(2)
    except ValueError:
        return "other", ""
    depth = 0
    while f is not None and depth < 60:
        name = f.f_globals.get("__name__", "") or ""
        if name == _TARGET_PREFIX or name.startswith(_TARGET_PREFIX + "."):
            return "plugin", "%s:%d" % (f.f_code.co_filename, f.f_lineno)
        f = f.f_back
        depth += 1
    return "other", ""


_LIB_ROOTS = tuple(sorted({p for p in (sys.prefix, sys.base_prefix, sys.exec_prefix,
                                       os.path.dirname(os.__file__)) if p}, key=len, reverse=True))


def _is_library_read(path, args):
    mode = str(args[1]) if len(args) > 1 else "r"
    if any(m in mode for m in ("w", "a", "x", "+")):
        return False
    return path.startswith(_LIB_ROOTS) or path.endswith((".pyc", ".py", ".so", ".pth"))


def _loopback(target):
    t = (target or "").lower()
    return (t in ("localhost", "127.0.0.1", "::1", "0.0.0.0") or t.startswith("127.")
            or t.endswith(".localhost"))


def _scan(args):
    """Find bait needles in the stringified event args."""
    try:
        blob = " ".join(str(a) for a in args).lower()
    except Exception:
        return []
    return [_NEEDLES[i] for i, n in enumerate(_NEEDLES_LC) if n and n in blob]


class _BlockEgress(PermissionError):
    pass


_PHASE = ["import"]
_ALLOW_EXEC = os.environ.get("XRAY_ALLOW_EXEC") == "1"


def set_phase(name):
    _PHASE[0] = name


def _cmd_target(event, args):
    """The program a spawn event runs. subprocess.Popen audits (executable, args, cwd, env) and
    executable is None unless passed explicitly (always on Windows), so fall back to argv[0]."""
    exe = args[0] if args else None
    argv = args[1] if len(args) > 1 else None
    if event == "subprocess.Popen" and exe is None:
        exe = argv
    if isinstance(exe, (list, tuple)):
        exe = exe[0] if exe else None
    if isinstance(exe, bytes):
        exe = exe.decode("utf-8", "replace")
    return "" if exe is None else str(exe)


def _hook(event, args):
    if getattr(_TLS, "busy", False):
        return
    kind = None
    if event in _WATCH:
        kind = _WATCH[event]
    elif event.startswith("os.exec") or event == "os.spawn" or event.startswith("subprocess"):
        kind = "subprocess"
    if kind is None and event == "import":
        name = args[0] if args else ""
        if name not in _IMPORTS_OF_INTEREST:
            return
        kind = "import"
    if kind is None:
        return

    # the first arg is the salient target for most events
    target = ""
    try:
        if event == "socket.getaddrinfo" or event == "socket.gethostbyname":
            target = str(args[0])
        elif event == "socket.connect":
            a = args[1] if len(args) > 1 else args[0]
            target = str(a[0]) if isinstance(a, (tuple, list)) and a else str(a)
        elif event == "urllib.Request":
            target = str(args[0])
        elif event == "import":
            target = str(args[0])
        elif kind == "subprocess":
            target = _cmd_target(event, args)
        else:
            target = str(args[0]) if args else ""
    except Exception:
        target = ""

    hits = _scan(args)
    if kind == "open" and not hits and _is_library_read(target, args):
        return
    origin, where = _origin()
    if kind in ("dynamic_code", "import", "native") and origin != "plugin":
        return
    if kind == "native" or (kind == "import" and target in ("ctypes", "cffi", "_cffi_backend")):
        if not _plugin_called_directly():
            return  # pulled in by a library or by Hermes itself, not by the plugin's own code
    if kind == "dynamic_code":
        try:
            imm = sys._getframe(1).f_globals.get("__name__", "") or ""
        except ValueError:
            imm = ""
        if not (imm == _TARGET_PREFIX or imm.startswith(_TARGET_PREFIX + ".")):
            return  # a library used exec internally (namedtuple, dataclasses); not the plugin
    if kind == "dynamic_code":
        co = args[0] if args else None
        fname = getattr(co, "co_filename", "") or ""
        if fname and not fname.startswith("<"):
            return  # executing a real file (module import), not built-at-runtime code
        target = fname or "<code>"
    outside = _outside_class(target) if kind in ("open", "listdir", "write", "delete") else ""
    if event in ("os.fork", "os.forkpty"):
        target = event[3:] + "()"
    rec = {"event": event, "kind": kind, "target": target[:300], "t": _time.time(),
           "origin": origin, "where": where, "phase": getattr(_TLS, "phase", None) or _PHASE[0]}
    if kind == "open" and len(args) > 1:
        rec["mode"] = str(args[1])
    if hits or kind in ("open", "connect", "dns", "http", "subprocess"):
        rec["via"] = _via()
    if hits:
        rec["bait"] = hits
    if outside:
        rec["outside"] = outside
    _emit(rec)

    # the chamber's HOME is fake, but the child still runs as the user; refuse the real secrets
    if outside == "real-credential":
        rec2 = dict(rec); rec2["blocked"] = True
        _emit(rec2)
        raise _BlockEgress(f"xray chamber refused a read of your real credential file {target!r}")

    # block real egress so nothing actually leaves the chamber; loopback is allowed for demos
    if kind in ("connect", "dns", "http") and not _loopback(target):
        rec2 = dict(rec); rec2["blocked"] = True
        _emit(rec2)
        raise _BlockEgress(f"xray chamber blocked egress to {target!r}")
    if kind == "subprocess" and not _ALLOW_EXEC:
        rec2 = dict(rec); rec2["blocked"] = True
        _emit(rec2)
        raise _BlockEgress(f"xray chamber blocked process spawn {target!r}")


sys.addaudithook(_hook)


# _posixsubprocess.fork_exec raises no audit event of its own, so a plugin calling it directly
# would skip the spawn block. Wrap it before anything binds it: subprocess' own calls (already
# audited as subprocess.Popen) pass through; any other caller is audited as a spawn.
try:
    import _posixsubprocess as _ps

    _real_fork_exec = _ps.fork_exec
    _SUBPROCESS_FILE = os.path.join(os.path.dirname(os.__file__), "subprocess.py")

    def _xray_fork_exec(*a, **k):
        try:
            caller = sys._getframe(1).f_code.co_filename
        except ValueError:
            caller = ""
        if os.path.normcase(caller) != os.path.normcase(_SUBPROCESS_FILE):
            argv = a[0] if a else None
            if isinstance(argv, (list, tuple)) and argv:
                argv = argv[0]
            if isinstance(argv, bytes):
                argv = argv.decode("utf-8", "replace")
            sys.audit("xray.fork_exec", str(argv), None)
        return _real_fork_exec(*a, **k)

    _ps.fork_exec = _xray_fork_exec
    if "subprocess" in sys.modules and hasattr(sys.modules["subprocess"], "_fork_exec"):
        sys.modules["subprocess"]._fork_exec = _xray_fork_exec
except ImportError:  # Windows has no _posixsubprocess
    pass


# ── clock warp (child only) ──────────────────────────────────────────────────
# Starts at real time so the plugin installs/registers "today"; the harness then calls
# ``warp_now()`` before exercising tools and hooks, so it sees N days pass since install.
_OFFSET = [0.0]
_real_time = _time.time
_RealDateTime = _dt.datetime
_RealDate = _dt.date


def warp_now():
    _OFFSET[0] = _WARP_DAYS * 86400.0


if _WARP_DAYS:
    _time.time = lambda: _real_time() + _OFFSET[0]  # type: ignore
    _real_time_ns = _time.time_ns
    _time.time_ns = lambda: _real_time_ns() + int(_OFFSET[0] * 1e9)  # type: ignore

    class _WarpedDateTime(_RealDateTime):
        @classmethod
        def now(cls, tz=None):
            return _RealDateTime.now(tz) + _dt.timedelta(seconds=_OFFSET[0])

        @classmethod
        def utcnow(cls):
            return _RealDateTime.utcnow() + _dt.timedelta(seconds=_OFFSET[0])

        @classmethod
        def today(cls):
            return cls.now()

    class _WarpedDate(_RealDate):
        @classmethod
        def today(cls):
            return (_RealDateTime.now() + _dt.timedelta(seconds=_OFFSET[0])).date()

    _dt.datetime = _WarpedDateTime  # type: ignore
    _dt.date = _WarpedDate  # type: ignore

_emit({"event": "xray.start", "kind": "meta", "target": "", "t": _time.time(),
       "warp_days": _WARP_DAYS})
