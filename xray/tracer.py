"""Runtime tracer: a process-wide audit hook, installed inside Hermes, that attributes file and
network events to the installed plugin that caused them, and raises an alert when a planted bait
file or honeytoken value is touched.

Observe-only: the hook never raises inside the Hermes process, so it can never break a session.
Blocking a flagged plugin is done separately, through the ``pre_tool_call`` hook and Hermes' own
human-approval gate.
"""

from __future__ import annotations

import os
import sys
import threading
from pathlib import Path
from typing import Callable, Dict, List, Optional, Set

_TLS = threading.local()
_SELF = "xray"


def _n(path: str) -> str:
    """Comparable spelling of a path on every OS (case, slashes, symlinks/junctions)."""
    try:
        return os.path.normcase(os.path.realpath(path))
    except (OSError, ValueError, TypeError):
        return os.path.normcase(str(path))


def _plugin_roots() -> Dict[str, str]:
    """Map each installed plugin's source directory -> plugin name. Built once; cheap."""
    roots: Dict[str, str] = {}
    try:
        from hermes_constants import get_hermes_home
        base = get_hermes_home() / "plugins"
        if base.is_dir():
            for d in base.iterdir():
                if d.is_dir():
                    roots[_n(str(d))] = d.name
    except Exception:
        pass
    for item in os.environ.get("XRAY_EXTRA_PLUGIN_ROOTS", "").split(os.pathsep):
        if item and Path(item).is_dir():
            roots[_n(item)] = Path(item).name
    return roots


class RuntimeTracer:
    def __init__(self, needles: List[str], decoy_paths: Dict[str, str],
                 on_alert: Callable[[dict], None]):
        self._needles = [n for n in needles if n]
        self._needles_lc = [n.lower() for n in self._needles]
        self._decoys = {_n(p): kind for p, kind in decoy_paths.items()}
        self._decoy_names = {os.path.basename(p) for p in self._decoys}
        self._on_alert = on_alert
        self._roots = _plugin_roots()
        self._root_items = sorted(self._roots.items(), key=lambda kv: len(kv[0]), reverse=True)
        self._installed = False
        self._fired: Set[tuple] = set()
        self._cache: Dict[str, Optional[str]] = {}

    def refresh_roots(self) -> None:
        self._roots = _plugin_roots()
        self._root_items = sorted(self._roots.items(), key=lambda kv: len(kv[0]), reverse=True)

    def install(self) -> None:
        if self._installed:
            return
        sys.addaudithook(self._hook)
        self._installed = True

    # which installed plugin is on the stack right now (nearest frame under a plugin dir)
    def _blame(self) -> Optional[str]:
        try:
            f = sys._getframe(2)
        except ValueError:
            return None
        depth = 0
        while f is not None and depth < 80:
            fn = f.f_code.co_filename
            plugin = self._cache.get(fn, False)
            if plugin is False:
                plugin = self._owner_of(fn)
                self._cache[fn] = plugin
            if plugin:
                return f"{plugin}\x00{fn}:{f.f_lineno}"
            f = f.f_back
            depth += 1
        return None

    def _owner_of(self, fn: str) -> Optional[str]:
        if not fn or fn.startswith("<"):
            return None
        nf = _n(fn)
        for root, name in self._root_items:
            if nf.startswith(root + os.sep):
                return name
        # the file may be loaded from a copy (plugin host staging): match ".../plugins/<name>/..."
        parts = nf.replace("\\", "/").split("/")
        for i, part in enumerate(parts[:-1]):
            if part == "plugins" and i + 1 < len(parts) - 1:
                cand = parts[i + 1]
                for name in self._roots.values():
                    if os.path.normcase(name) == cand and name != _SELF:
                        return name
        return None

    def _nearest_code(self) -> str:
        """For an unattributed read: the first frame outside the stdlib and X-Ray itself."""
        try:
            f = sys._getframe(3)
        except ValueError:
            return ""
        stdlib = _n(os.path.dirname(os.__file__))
        me = _n(os.path.dirname(__file__))
        while f is not None:
            fn = f.f_code.co_filename
            nf = _n(fn) if not fn.startswith("<") else fn
            if not fn.startswith("<") and not nf.startswith(stdlib) and not nf.startswith(me):
                return f"{fn}:{f.f_lineno}"
            f = f.f_back
        return ""

    def _match_needle(self, args) -> List[str]:
        if not self._needles_lc:
            return []
        try:
            blob = " ".join(str(a) for a in args).lower()
        except Exception:
            return []
        return [self._needles[i] for i, n in enumerate(self._needles_lc) if n in blob]

    def _hook(self, event: str, args) -> None:
        if getattr(_TLS, "busy", False):
            return
        try:
            is_open = event == "open"
            is_net = event in ("socket.connect", "socket.getaddrinfo", "socket.gethostbyname",
                               "urllib.Request", "http.client.connect")
            if not (is_open or is_net):
                return
            target = ""
            decoy_kind = None
            if is_open and args:
                target = str(args[0])
                if os.path.basename(target) not in self._decoy_names:
                    return
                decoy_kind = self._decoys.get(_n(target))
            needle_hits = self._match_needle(args) if (is_net or not is_open) else []
            if is_open and not decoy_kind:
                needle_hits = []  # opening a non-decoy file is not interesting on its own
            if not decoy_kind and not needle_hits:
                return
            _TLS.busy = True
            blame = self._blame()
            if blame:
                plugin, where = blame.split("\x00", 1)
            elif decoy_kind:
                # touched, but not from an installed plugin's code (core, a skill, a shell tool):
                # still worth showing, at a lower severity, so a miss is never silent
                plugin, where = "(unattributed)", self._nearest_code()
            else:
                return
            key = (plugin, event, decoy_kind or tuple(needle_hits), where)
            if key in self._fired:
                return
            self._fired.add(key)
            if decoy_kind:
                detail = f"read planted bait file ({decoy_kind})"
                kind = "bait-file-read"
            else:
                detail = f"honeytoken value appeared in a {event} ({len(needle_hits)} token)"
                kind = "honeytoken-egress"
            self._on_alert({"plugin": plugin,
                            "severity": "RED" if blame else "INFO", "kind": kind,
                            "detail": detail, "location": where, "event": event,
                            "target": target[:200]})
        except Exception:
            pass
        finally:
            _TLS.busy = False
