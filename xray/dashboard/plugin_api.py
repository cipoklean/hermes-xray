"""Backend for the Plugin X-Ray Desktop page: /api/plugins/xray/…

Reads X-Ray's own plugin-data db; `POST /detonate` runs a detonation in a worker thread and
pushes `plugin.xray.detonation.done` to the Desktop when it finishes.
"""

from __future__ import annotations

import importlib.util
import sys
import threading
from pathlib import Path

from fastapi import APIRouter

router = APIRouter()
_PKG = "xray_desktop_core"
_RUNNING: dict = {}


def _core():
    """Load X-Ray's own package (the parent dir) under a private name, without register()."""
    if _PKG in sys.modules:
        return sys.modules[_PKG]
    root = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location(_PKG, root / "__init__.py",
                                                  submodule_search_locations=[str(root)])
    mod = importlib.util.module_from_spec(spec)
    sys.modules[_PKG] = mod
    spec.loader.exec_module(mod)
    return mod


def _store():
    _core()
    return importlib.import_module(_PKG + ".store")


def _push(event: str, payload: dict) -> None:
    try:
        from hermes_cli.plugin_events import broadcast_plugin_event
        broadcast_plugin_event("xray", event, payload)
    except Exception:
        pass


@router.get("/verdicts")
async def verdicts():
    st = _store()
    rows = []
    for name, d in sorted(st.latest_verdicts().items()):
        r = d["result"]
        rows.append({"plugin": name, "sha": d["sha"], "verdict": d["verdict"], "ts": d["ts"],
                     "fingerprint": d["fp_hash"], "reasons": r.get("reasons", []),
                     "amber": r.get("amber", []), "hosts": r.get("hosts", []),
                     "commands": r.get("commands", []), "bait_hits": r.get("bait_hits", [])[:8],
                     "sanctioned": r.get("sanctioned", [])[:6],
                     "warp_only": r.get("warp_only", []), "disclosure": r.get("disclosure", "")})
    return {"plugins": rows, "running": sorted(_RUNNING)}


@router.get("/alerts")
async def alerts():
    return {"alerts": _store().alerts(limit=50)}


@router.get("/history/{plugin}")
async def history(plugin: str):
    st = _store()
    rows = st.detonations(plugin, limit=10)
    cli = importlib.import_module(_PKG + ".cli")
    diff = cli.behaviour_diff(rows[1], rows[0]) if len(rows) >= 2 else []
    return {"plugin": plugin, "versions": [{"sha": r["sha"], "verdict": r["verdict"], "ts": r["ts"],
                                            "fingerprint": r["fp_hash"]} for r in rows],
            "diff": diff}


@router.post("/detonate")
async def detonate(body: dict):
    target = str((body or {}).get("target", "")).strip()
    if not target:
        return {"ok": False, "error": "target required"}
    if target in _RUNNING:
        return {"ok": True, "running": True}

    def work():
        try:
            core = _core()
            cli = importlib.import_module(_PKG + ".cli")
            chamber = importlib.import_module(_PKG + ".chamber")
            analysis = importlib.import_module(_PKG + ".analysis")
            st = _store()
            d, name, sha, tmp = cli.resolve_target(target, str(body.get("subdir", "") or ""))
            det = chamber.detonate(d)
            res = analysis.analyze(det, cli._declared_texts(d, []))
            st.save_detonation(name, sha, res)
            _push("detonation.done", {"plugin": name, "verdict": res["verdict"]})
            if tmp:
                import shutil
                shutil.rmtree(tmp, ignore_errors=True)
        except BaseException as exc:  # report, never crash the gateway
            _push("detonation.failed", {"target": target, "error": str(exc)[:200]})
        finally:
            _RUNNING.pop(target, None)

    _RUNNING[target] = True
    threading.Thread(target=work, name="xray-detonate", daemon=True).start()
    return {"ok": True, "running": True}
