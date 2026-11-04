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


def _plugin_roots() -> Dict[str, str]:
    """Map each installed plugin's source directory -> plugin name. Built once; cheap."""
    roots: Dict[str, str] = {}
    try:
        from hermes_constants import get_hermes_home
        base = get_hermes_home() / "plugins"
        if base.is_dir():
            for d in base.iterdir():
                if d.is_dir():
                    roots[str(d.resolve())] = d.name
    except Exception:
        pass
    for item in os.environ.get("XRAY_EXTRA_PLUGIN_ROOTS", "").split(os.pathsep):
        if item and Path(item).is_dir():
            roots[str(Path(item).resolve())] = Path(item).name
    return roots


class RuntimeTracer:
    def __init__(self, needles: List[str], decoy_paths: Dict[str, str],
                 on_alert: Callable[[dict], None]):
        self._needles = [n for n in needles if n]
        self._needles_lc = [n.lower() for n in self._needles]
        self._decoys = {str(Path(p).resolve()): kind for p, kind in decoy_paths.items()}
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
                plugin = None
                for root, name in self._root_items:
                    if fn.startswith(root + os.sep):
                        plugin = name
                        break
                self._cache[fn] = plugin
            if plugin:
                return f"{plugin}\x00{fn}:{f.f_lineno}"
            f = f.f_back
            depth += 1
        return None

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
                try:
                    decoy_kind = self._decoys.get(str(Path(target).resolve()))
                except Exception:
                    decoy_kind = None
            needle_hits = self._match_needle(args) if (is_net or not is_open) else []
            if is_open and not decoy_kind:
                needle_hits = []  # opening a non-decoy file is not interesting on its own
            if not decoy_kind and not needle_hits:
                return
            _TLS.busy = True
            blame = self._blame()
            if not blame:
                return
            plugin, where = blame.split("\x00", 1)
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
            self._on_alert({"plugin": plugin, "severity": "RED", "kind": kind,
                            "detail": detail, "location": where, "event": event,
                            "target": target[:200]})
        except Exception:
            pass
        finally:
            _TLS.busy = False
