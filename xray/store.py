"""Persistence: detonation results and runtime alerts in X-Ray's own plugin-data SQLite db."""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from pathlib import Path
from typing import List, Optional

_LOCK = threading.Lock()
_SCHEMA = """
CREATE TABLE IF NOT EXISTS detonations (
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL, plugin TEXT NOT NULL,
  sha TEXT NOT NULL, verdict TEXT NOT NULL, fp_hash TEXT NOT NULL, result_json TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS det_plugin ON detonations(plugin, ts);
CREATE TABLE IF NOT EXISTS alerts (
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL, plugin TEXT NOT NULL,
  severity TEXT NOT NULL, kind TEXT NOT NULL, detail TEXT NOT NULL, location TEXT);
CREATE INDEX IF NOT EXISTS alert_plugin ON alerts(plugin, ts);
"""


def data_dir() -> Path:
    override = os.environ.get("XRAY_DATA_DIR")
    if override:
        p = Path(override)
        p.mkdir(parents=True, exist_ok=True)
        return p
    try:
        from plugins.plugin_storage import plugin_data_dir
        return plugin_data_dir("xray")
    except Exception:
        p = Path.home() / ".xray"
        p.mkdir(parents=True, exist_ok=True)
        return p


def _connect() -> sqlite3.Connection:
    conn = None
    if not os.environ.get("XRAY_DATA_DIR"):
        try:
            from plugins.plugin_storage import plugin_db
            conn = plugin_db("xray")
        except Exception:
            conn = None
    if conn is None:
        conn = sqlite3.connect(str(data_dir() / "data.db"), check_same_thread=False)
    conn.executescript(_SCHEMA)
    return conn


_CONN: Optional[sqlite3.Connection] = None


def conn() -> sqlite3.Connection:
    global _CONN
    with _LOCK:
        if _CONN is None:
            _CONN = _connect()
        return _CONN


def save_detonation(plugin: str, sha: str, res: dict) -> int:
    c = conn()
    with _LOCK:
        cur = c.execute(
            "INSERT INTO detonations(ts, plugin, sha, verdict, fp_hash, result_json) VALUES (?,?,?,?,?,?)",
            (time.time(), plugin, sha, res["verdict"], res["fingerprint"]["hash"],
             json.dumps({k: v for k, v in res.items() if k != "per_warp"})))
        c.commit()
        return int(cur.lastrowid)


def detonations(plugin: Optional[str] = None, limit: int = 50) -> List[dict]:
    c = conn()
    q = "SELECT id, ts, plugin, sha, verdict, fp_hash, result_json FROM detonations"
    args: tuple = ()
    if plugin:
        q += " WHERE plugin = ?"
        args = (plugin,)
    q += " ORDER BY ts DESC LIMIT ?"
    with _LOCK:
        rows = c.execute(q, args + (limit,)).fetchall()
    return [{"id": r[0], "ts": r[1], "plugin": r[2], "sha": r[3], "verdict": r[4],
             "fp_hash": r[5], "result": json.loads(r[6])} for r in rows]


def latest_verdicts() -> dict:
    out = {}
    for d in reversed(detonations(limit=500)):
        out[d["plugin"]] = d
    return out


def by_sha(plugin: str, sha: str) -> Optional[dict]:
    for d in detonations(plugin, limit=200):
        if d["sha"] == sha or d["sha"].startswith(sha):
            return d
    return None


def add_alert(plugin: str, severity: str, kind: str, detail: str, location: str = "") -> None:
    c = conn()
    with _LOCK:
        c.execute("INSERT INTO alerts(ts, plugin, severity, kind, detail, location) VALUES (?,?,?,?,?,?)",
                  (time.time(), plugin, severity, kind, detail[:500], location[:300]))
        c.commit()


def alerts(limit: int = 50, plugin: Optional[str] = None) -> List[dict]:
    c = conn()
    q = "SELECT ts, plugin, severity, kind, detail, location FROM alerts"
    args: tuple = ()
    if plugin:
        q += " WHERE plugin = ?"
        args = (plugin,)
    q += " ORDER BY ts DESC LIMIT ?"
    with _LOCK:
        rows = c.execute(q, args + (limit,)).fetchall()
    return [{"ts": r[0], "plugin": r[1], "severity": r[2], "kind": r[3], "detail": r[4],
             "location": r[5]} for r in rows]
