"""Turn raw detonation runs into a verdict, a behaviour fingerprint, and a disclosure line.

Verdict:
  RED   — the plugin read bait, or a bait value appeared in an outbound URL/DNS/command/write,
          or it only misbehaved after the clock was warped (a time-bomb).
  AMBER — undisclosed real-world reach: a non-loopback host, a subprocess, a write outside its
          own data/config area, or dynamic code execution.
  GREEN — none of the above.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from typing import Dict, List
from urllib.parse import urlparse

_HOST_RE = re.compile(r"[a-z0-9.-]+\.[a-z]{2,}", re.I)


def _host_of(kind: str, target: str) -> str:
    if not target:
        return ""
    if kind == "http":
        try:
            h = urlparse(target).hostname or ""
            return h.lower()
        except ValueError:
            return ""
    if kind == "dns":
        return target.strip().lower()
    if kind == "connect":
        return target.strip().lower()
    return ""


def _path_class(path: str, home: str, hermes_home: str) -> str:
    p = (path or "").replace("\\", "/")
    if not p or p.startswith("<"):
        return ""
    data = (hermes_home + "/plugin-data").replace("\\", "/")
    if p.startswith(data):
        return "own-data"
    if "/.ssh/" in p or "/.aws/" in p or p.endswith(".env") or "/solana/" in p \
            or "wallet" in p or "credentials" in p or "/.git-credentials" in p \
            or "auth.json" in p or "/memories/" in p:
        return "credential-store"
    if p.startswith(hermes_home.replace("\\", "/")):
        return "hermes-home"
    if p.startswith(home.replace("\\", "/")):
        return "home"
    if p.startswith("/etc") or p.startswith("/proc") or p.startswith("/sys"):
        return "system"
    return "other"


# Where each honeytoken legitimately goes. A key sent to its own provider is normal use.
PROVIDER_HOSTS = {
    "openai_key": ("openai.com", "openrouter.ai"), "anthropic_key": ("anthropic.com",),
    "aws_access_key": ("amazonaws.com",), "aws_secret_key": ("amazonaws.com",),
    "github_token": ("github.com", "githubusercontent.com"), "telegram_token": ("telegram.org",),
}
_SANCTIONED_FILES = ("hermes_env", "hermes_auth")  # read on the plugin's behalf by Hermes' secret API


def _token_kinds(values: List[str], world: dict) -> List[str]:
    tk = world.get("token_kinds", {})
    kinds = sorted({tk[v] for v in values if v in tk})
    return kinds


def _to_own_provider(kinds: List[str], host: str) -> bool:
    if not kinds or not host:
        return False
    return all(any(host == d or host.endswith("." + d) for d in PROVIDER_HOSTS.get(k, ())) for k in kinds)


def _short_where(where: str, world: dict) -> str:
    """'/tmp/xray-chamber-x/home/.hermes/plugins/foo/__init__.py:22' -> 'foo/__init__.py:22'."""
    marker = "/plugins/"
    w = (where or "").replace("\\", "/")
    return w.split(marker, 1)[1] if marker in w else os.path.basename(w)


def _redact(text: str, values: List[str]) -> str:
    for v in values:
        text = re.sub(re.escape(v), "[BAIT]", text, flags=re.I)
    return text


def summarize_run(run: dict, world: dict) -> dict:
    home, hhome = world["home"], world["hermes_home"]
    bait_paths = {f["path"]: f["kind"] for f in world.get("files", [])}
    hosts, cmds, writes, reads, baited, dyn = set(), set(), set(), set(), [], False
    sanctioned = []
    egress_blocked = set()
    for e in run.get("events", []):
        kind, target = e.get("kind"), e.get("target", "")
        where = _short_where(e.get("where", ""), world)
        via = e.get("via", "")
        if e.get("bait") and kind != "open":
            kinds = _token_kinds(e["bait"], world)
            host = _host_of(kind, target)
            entry = {"kind": kind, "target": _redact(target, e["bait"])[:160], "where": where,
                     "tokens": kinds, "phase": e.get("phase"), "via": via}
            if _to_own_provider(kinds, host):
                sanctioned.append(dict(entry, note=f"{'/'.join(kinds)} sent to its own provider {host}"))
            else:
                baited.append(entry)
        elif kind == "open" and target in bait_paths:
            entry = {"kind": "read", "target": "~/" + os.path.relpath(target, home),
                     "bait": bait_paths[target], "where": where, "phase": e.get("phase"), "via": via}
            if bait_paths[target] in _SANCTIONED_FILES and via.startswith("hermes:"):
                sanctioned.append(dict(entry, note=f"{bait_paths[target]} read by Hermes ({via[7:]}) "
                                                   "on the plugin's behalf"))
            else:
                baited.append(entry)
            continue
        by_hermes = via.startswith("hermes:")
        if by_hermes and kind in ("open", "write", "delete", "listdir", "subprocess"):
            continue  # Hermes' own code doing its job (config, credential pool, platform probes)
        if kind in ("connect", "dns", "http"):
            h = _host_of(kind, target)
            if h:
                (egress_blocked if e.get("blocked") else hosts).add(h)
        elif kind == "subprocess":
            cmds.add(_cmd_name(target))
        elif kind == "open":
            pc = _path_class(target, home, hhome)
            mode = e.get("mode", "")
            (writes if any(m in mode for m in ("w", "a", "x", "+")) else reads).add(pc or "other")
        elif kind in ("write", "delete"):
            writes.add(_path_class(target, home, hhome) or "other")
        elif kind == "listdir":
            reads.add(_path_class(target, home, hhome) or "other")
        elif kind == "dynamic_code":
            dyn = True
    reads.discard("")
    writes.discard("")
    return {"warp_days": run.get("warp_days"), "hosts": sorted(hosts),
            "egress_blocked": sorted(egress_blocked), "commands": sorted(cmds),
            "writes": sorted(writes), "reads": sorted(reads), "bait_hits": baited,
            "sanctioned": sanctioned,
            "dynamic_code": dyn, "crash": run.get("crash"), "timed_out": run.get("timed_out")}


def declared_hosts(texts: List[str]) -> List[str]:
    """Hosts a plugin admits to in its own manifest/README/catalog entry."""
    found = set()
    for t in texts:
        for m in _HOST_RE.findall(t or ""):
            m = m.lower().strip(".")
            if "." in m and not m.endswith((".py", ".md", ".yaml", ".yml", ".json", ".txt", ".js")):
                found.add(m)
    return sorted(found)


def _disclosed(host: str, declared: List[str]) -> bool:
    return any(host == d or host.endswith("." + d) or d.endswith("." + host) for d in declared)


def _cmd_name(target: str) -> str:
    """Program name from a spawn target on any OS: 'C:\\Windows\\curl.exe' -> 'curl'."""
    t = (target or "").strip()
    if t.startswith('"'):
        first = t[1:].split('"', 1)[0]
    elif re.match(r"^[A-Za-z]:[\\/]", t) and (".exe" in t.lower()):
        first = t[: t.lower().index(".exe") + 4]
    else:
        first = t.split()[0] if t else ""
    if not first or first == "None":
        return "?"
    name = re.split(r"[\\/]", first)[-1]
    return re.sub(r"\.(exe|cmd|bat|com)$", "", name, flags=re.I) or "?"


def analyze(detonation: dict, declared_texts: List[str] = ()) -> dict:
    world = detonation["world"]
    per = [summarize_run(r, world) for r in detonation["runs"]]
    base = next((s for s in per if s["warp_days"] == 0), per[0] if per else {})

    union_hosts, union_cmds, union_writes, union_reads = set(), set(), set(), set()
    all_bait, warp_only, sanctioned = [], [], []
    dyn = False
    for s in per:
        union_hosts |= set(s["hosts"]) | set(s["egress_blocked"])
        union_cmds |= set(s["commands"])
        union_writes |= set(s["writes"])
        union_reads |= set(s["reads"])
        dyn = dyn or s["dynamic_code"]
        all_bait += [dict(b, warp_days=s["warp_days"]) for b in s["bait_hits"]]
        for x in s["sanctioned"]:
            if x["note"] not in {y["note"] for y in sanctioned}:
                sanctioned.append(dict(x, warp_days=s["warp_days"]))
        if s["warp_days"] and base:
            new_h = (set(s["hosts"]) | set(s["egress_blocked"])) - (set(base["hosts"]) | set(base["egress_blocked"]))
            new_c = set(s["commands"]) - set(base["commands"])
            if new_h or new_c:
                warp_only.append({"warp_days": s["warp_days"], "new_hosts": sorted(new_h),
                                  "new_commands": sorted(new_c)})

    seen, uniq = set(), []
    for b in all_bait:
        key = (b["kind"], b["target"], b["where"], b.get("phase"))
        if key not in seen:
            seen.add(key)
            uniq.append(b)
    all_bait = uniq
    exfil = [b for b in all_bait if b["kind"] in ("http", "dns", "connect", "subprocess", "write")]

    reasons, verdict = [], "GREEN"
    amber = []
    reads_b = [b for b in all_bait if b["kind"] == "read"]
    if reads_b:
        kinds = sorted({b["bait"] for b in reads_b})
        hermes_only = all(k in _SANCTIONED_FILES for k in kinds)
        if hermes_only:
            reasons.append("reads the Hermes secrets file itself instead of asking "
                           "agent.secret_scope (catalog rule 11): " + ", ".join(kinds)
                           + f" (at {reads_b[0]['where']})")
        else:
            reasons.append("read bait credential files: " + ", ".join(kinds)
                           + f" (at {reads_b[0]['where']})")
    if exfil:
        dests = sorted({(_host_of(b["kind"], b["target"]) or b["target"][:40]) for b in exfil})
        reasons.append("honeytoken values sent out toward: " + ", ".join(dests[:4])
                       + f" (at {exfil[0]['where']})")
    if warp_only:
        reasons.append("new behaviour only after clock warp (possible time-bomb): "
                       + "; ".join(f"+{w['warp_days']}d {w['new_hosts']+w['new_commands']}" for w in warp_only))
    if reasons:
        verdict = "RED"

    declared = declared_hosts(list(declared_texts))
    undisclosed = sorted(h for h in union_hosts if not _disclosed(h, declared))
    if undisclosed:
        amber.append("contacts undisclosed host(s): " + ", ".join(undisclosed))
    if union_cmds:
        amber.append("runs command(s): " + ", ".join(sorted(union_cmds)))
    if union_writes & {"hermes-home", "home", "system", "other"}:
        amber.append("writes outside its data dir: " + ", ".join(sorted(union_writes & {"hermes-home","home","system","other"})))
    if dyn:
        amber.append("executes dynamically built code")
    if verdict == "GREEN" and amber:
        verdict = "AMBER"

    fp = fingerprint(union_hosts, union_cmds, union_writes, union_reads, dyn, bool(all_bait))
    return {"verdict": verdict, "reasons": reasons, "amber": amber, "per_warp": per,
            "hosts": sorted(union_hosts), "commands": sorted(union_cmds),
            "writes": sorted(union_writes), "reads": sorted(union_reads),
            "dynamic_code": dyn, "bait_hits": all_bait, "warp_only": warp_only,
            "undisclosed_hosts": undisclosed, "sanctioned": sanctioned, "fingerprint": fp,
            "disclosure": disclosure(sorted(union_hosts), sorted(union_cmds), sorted(union_writes),
                                     dyn, "credential-store" in union_reads)}


def fingerprint(hosts, cmds, writes, reads, dyn, bait) -> dict:
    body = {"hosts": sorted(hosts), "commands": sorted(cmds), "writes": sorted(writes),
            "reads": sorted(reads), "dynamic_code": bool(dyn), "touches_bait": bool(bait)}
    digest = hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()[:16]
    return {"hash": digest, **body}


def disclosure(hosts, cmds, writes, dyn, reads_creds=False) -> str:
    parts = []
    if reads_creds:
        parts.append("READS CREDENTIAL FILES (keys, tokens, wallet)")
    if hosts:
        parts.append("contacts " + ", ".join(hosts))
    else:
        parts.append("makes no network connections")
    if cmds:
        parts.append("runs `" + "`, `".join(cmds) + "`")
    outside = [w for w in writes if w not in ("own-data",)]
    if outside:
        parts.append("writes to " + ", ".join(outside))
    else:
        parts.append("writes only inside its own data dir")
    if dyn:
        parts.append("executes dynamically generated code")
    return "Disclosure — " + "; ".join(parts) + "."
