"""`hermes xray …` — command-line surface. Also importable standalone: `python -m xray …`."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import List, Optional, Tuple

from . import analysis, bait, report, store
from . import chamber

_GIT_URL = re.compile(r"^(https://|git@)|^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(@[0-9a-f]{7,40})?$")


# ── target resolution ────────────────────────────────────────────────────────

def _installed_dir(name: str) -> Optional[Path]:
    try:
        from hermes_constants import get_hermes_home
        p = get_hermes_home() / "plugins" / name
        if (p / "plugin.yaml").is_file() or (p / "__init__.py").is_file():
            return p
    except Exception:
        pass
    return None


def _tree_sha(d: Path) -> str:
    h = hashlib.sha256()
    for f in sorted(d.rglob("*")):
        if f.is_file() and ".git" not in f.parts and "__pycache__" not in f.parts:
            h.update(str(f.relative_to(d)).encode())
            h.update(f.read_bytes())
    return "tree:" + h.hexdigest()[:12]


def _git_sha(d: Path) -> str:
    try:
        out = subprocess.run(["git", "-C", str(d), "rev-parse", "HEAD"], capture_output=True,
                             text=True, timeout=10)
        if out.returncode == 0 and re.fullmatch(r"[0-9a-f]{40}", out.stdout.strip()):
            top = subprocess.run(["git", "-C", str(d), "rev-parse", "--show-toplevel"],
                                 capture_output=True, text=True, timeout=10).stdout.strip()
            dirty = subprocess.run(["git", "-C", str(d), "status", "--porcelain", "--", "."],
                                   capture_output=True, text=True, timeout=10).stdout.strip()
            if top and not dirty:
                if Path(top).resolve() == d.resolve():
                    return out.stdout.strip()
                # a plugin in a repo subdir: two subdirs at one commit are different code, so key
                # them by the subdir's own git tree id (what `catalog subdir:` installs)
                tree = subprocess.run(["git", "-C", str(d), "rev-parse", "HEAD:./"],
                                      capture_output=True, text=True, timeout=10).stdout.strip()
                if re.fullmatch(r"[0-9a-f]{40}", tree):
                    return tree
    except (OSError, subprocess.SubprocessError):
        pass
    return _tree_sha(d)


def resolve_target(target: str, subdir: str = "") -> Tuple[Path, str, str, Optional[Path]]:
    """-> (plugin_dir, plugin_name, sha, tempdir_to_cleanup)."""
    p = Path(target).expanduser()
    if p.is_dir():
        d = p / subdir if subdir else p
        return d.resolve(), _manifest_name(d) or d.name, _git_sha(d), None
    inst = _installed_dir(target)
    if inst:
        return inst, target, _git_sha(inst), None
    if _GIT_URL.search(target):
        url, _, sha = target.partition("@") if not target.startswith("git@") else (target, "", "")
        if not url.startswith(("https://", "git@")):
            url = f"https://github.com/{url}"
        tmp = Path(tempfile.mkdtemp(prefix="xray-src-"))
        subprocess.run(["git", "clone", "--quiet", "--filter=blob:limit=5m", url, str(tmp / "repo")],
                       check=True, timeout=180)
        if sha:
            subprocess.run(["git", "-C", str(tmp / "repo"), "checkout", "--quiet", sha], check=True,
                           timeout=60)
        d = tmp / "repo" / subdir if subdir else tmp / "repo"
        real_sha = subprocess.run(["git", "-C", str(tmp / "repo"), "rev-parse", "HEAD"],
                                  capture_output=True, text=True).stdout.strip()
        return d, _manifest_name(d) or Path(url).stem, real_sha, tmp
    raise SystemExit(f"xray: cannot find plugin {target!r} (path, installed name, or git repo)")


def _manifest_name(d: Path) -> str:
    for fn in ("plugin.yaml", "plugin.yml"):
        f = d / fn
        if f.is_file():
            m = re.search(r"^name:\s*['\"]?([A-Za-z0-9_./-]+)", f.read_text(encoding="utf-8",
                                                                            errors="replace"), re.M)
            if m:
                return m.group(1)
    return ""


def _declared_texts(d: Path, extra: List[str]) -> List[str]:
    texts = []
    for fn in ("plugin.yaml", "plugin.yml", "README.md", "plugin.json"):
        f = d / fn
        if f.is_file():
            texts.append(f.read_text(encoding="utf-8", errors="replace"))
    for e in extra or []:
        try:
            texts.append(Path(e).read_text(encoding="utf-8", errors="replace"))
        except OSError:
            pass
    return texts


# ── commands ─────────────────────────────────────────────────────────────────

def cmd_detonate(a) -> int:
    d, name, sha, tmp = resolve_target(a.target, a.subdir or "")
    if not (d / "__init__.py").is_file():
        print(f"xray: {name} has no __init__.py (manifest-only / portable package): nothing to detonate.")
        return 0
    warps = tuple(int(x) for x in a.warps.split(",") if x.strip() != "")
    if not a.json:
        print(f"⚗️  Detonating {name} @ {sha[:12]} in a throwaway chamber "
              f"(fake home with bait, egress and spawns blocked, clock {', '.join(('+%dd' % w) if w else 'now' for w in warps)})…")
    try:
        det = chamber.detonate(d, warps=warps, allow_exec=a.allow_exec, fuzz_rounds=a.rounds,
                               per_call_timeout=a.timeout, keep=a.keep)
        res = analysis.analyze(det, _declared_texts(d, a.entry))
    finally:
        if tmp:
            shutil.rmtree(tmp, ignore_errors=True)
    errs = [r for r in det["runs"] if r.get("crash")]
    res["registered"] = next((r["registered"] for r in det["runs"] if r.get("registered")), None)
    store.save_detonation(name, sha, res)
    if a.json:
        print(report.to_json(name, res, sha))
    else:
        print(report.render(f"{name} @ {sha[:12]}", res))
        reg = res.get("registered") or {}
        print(f"  exercised: {len(reg.get('tools', []))} tool(s), {len(reg.get('hooks', []))} hook(s), "
              f"{len(reg.get('commands', []))} command(s), {reg.get('calls', 0)} call(s) per clock")
        if errs:
            print("  note: harness crashed in a run:", errs[0]["crash"][-160:])
    return {"RED": 2, "AMBER": 1}.get(res["verdict"], 0) if a.ci else 0


def cmd_verdicts(a) -> int:
    rows = store.latest_verdicts()
    if not rows:
        print("No detonations yet. Try: hermes xray detonate <plugin>")
        return 0
    print(f"{'PLUGIN':28} {'VERDICT':7} {'SHA':14} {'FINGERPRINT':16} WHEN")
    for name, d in sorted(rows.items()):
        when = time.strftime("%Y-%m-%d %H:%M", time.localtime(d["ts"]))
        print(f"{name[:28]:28} {d['verdict']:7} {d['sha'][:12]:14} {d['fp_hash']:16} {when}")
    return 0


def _pick(plugin: str, sha: Optional[str]):
    if sha:
        d = store.by_sha(plugin, sha)
    else:
        rows = store.detonations(plugin, limit=1)
        d = rows[0] if rows else None
    if not d:
        raise SystemExit(f"xray: no detonation stored for {plugin}{' @ ' + sha if sha else ''}")
    return d


def cmd_show(a) -> int:
    d = _pick(a.plugin, a.sha)
    if a.json:
        print(json.dumps(d, indent=2))
    else:
        print(report.render(f"{d['plugin']} @ {d['sha'][:12]}", d["result"]))
    return 0


def behaviour_diff(old: dict, new: dict) -> List[str]:
    out = []
    of, nf = old["result"]["fingerprint"], new["result"]["fingerprint"]
    for key, label in (("hosts", "host"), ("commands", "command"), ("writes", "writes to"),
                       ("reads", "reads")):
        added = sorted(set(nf.get(key, [])) - set(of.get(key, [])))
        removed = sorted(set(of.get(key, [])) - set(nf.get(key, [])))
        out += [f"+ {label} {x}" for x in added] + [f"- {label} {x}" for x in removed]
    for flag, label in (("dynamic_code", "executes dynamic code"), ("touches_bait", "touches bait"),
                        ("native_code", "loads native code")):
        if nf.get(flag) and not of.get(flag):
            out.append(f"+ {label}")
        elif of.get(flag) and not nf.get(flag):
            out.append(f"- {label}")
    if old["verdict"] != new["verdict"]:
        out.append(f"! verdict {old['verdict']} → {new['verdict']}")
    return out


def cmd_diff(a) -> int:
    if a.old and a.new:
        old, new = _pick(a.plugin, a.old), _pick(a.plugin, a.new)
    else:
        rows = store.detonations(a.plugin, limit=2)
        if len(rows) < 2:
            raise SystemExit("xray: need two detonations of this plugin (two versions) to diff")
        new, old = rows[0], rows[1]
    lines = behaviour_diff(old, new)
    print(f"Behaviour diff for {a.plugin}: {old['sha'][:12]} → {new['sha'][:12]}")
    if not lines:
        print("  (no behaviour change — same fingerprint %s)" % new["fp_hash"])
    for l in lines:
        print("  " + l)
    return 1 if (a.ci and lines) else 0


def cmd_disclose(a) -> int:
    d = _pick(a.plugin, a.sha)
    print(d["result"]["disclosure"])
    return 0


def cmd_bait(a) -> int:
    reg_file = Path(store.data_dir()) / "live-bait.json"
    if a.action == "plant":
        files = bait.plant(Path.home(), reg_file)
        if not files:
            print("No empty bait locations found (X-Ray never overwrites a real file).")
            return 0
        print(f"🪤 Planted {len(files)} decoy file(s). They hold fake, traceable values only:")
        for f in files:
            print(f"   {f['kind']:16} {f['path']}")
        print("Remove anytime with: hermes xray bait remove")
    elif a.action == "remove":
        removed = bait.remove(reg_file)
        print(f"Removed {len(removed)} decoy file(s).")
    else:
        reg = bait.load_registry(reg_file)
        files = reg.get("files", [])
        print(f"{len(files)} decoy file(s) planted." if files else "No bait planted.")
        for f in files:
            print(f"   {f['kind']:16} {f['path']}  {'present' if Path(f['path']).exists() else 'MISSING'}")
        hb = Path(store.data_dir()) / "tracer.json"
        try:
            h = json.loads(hb.read_text(encoding="utf-8"))
            when = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(h["ts"]))
            print(f"Runtime tracer last armed {when} (pid {h['pid']}), watching "
                  f"{h['decoys']} decoy(s) and plugins: {', '.join(h['plugins']) or '(none)'}")
        except (OSError, ValueError, KeyError):
            if files:
                print("Runtime tracer not armed yet: start a new `hermes` chat (it arms on session start).")
    return 0


def cmd_alerts(a) -> int:
    rows = store.alerts(limit=a.limit)
    if not rows:
        print("No runtime alerts. (Plant bait with: hermes xray bait plant)")
        return 0
    for r in rows:
        when = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(r["ts"]))
        print(f"{when}  {r['severity']:5} {r['plugin']:24} {r['detail']}  @ {r['location']}")
    return 0


def summary_text() -> str:
    rows = store.latest_verdicts()
    alerts = store.alerts(limit=5)
    lines = ["Plugin X-Ray"]
    if rows:
        for name, d in sorted(rows.items()):
            lines.append(f"  {d['verdict']:5}  {name}  ({d['sha'][:10]})")
    else:
        lines.append("  no detonations yet — run `hermes xray detonate <plugin>`")
    if alerts:
        lines.append("Recent bait alerts:")
        lines += [f"  {r['severity']} {r['plugin']}: {r['detail']}" for r in alerts]
    return "\n".join(lines)


# ── argparse ─────────────────────────────────────────────────────────────────

def setup_argparse(sub) -> None:
    sp = sub.add_subparsers(dest="xray_cmd")
    d = sp.add_parser("detonate", help="Run a plugin in the bait-filled sandbox and score it")
    d.add_argument("target", help="plugin dir, installed plugin name, owner/repo[@sha] or git URL")
    d.add_argument("--subdir", default="", help="plugin subdirectory inside the repo")
    d.add_argument("--warps", default="0,30,90", help="clock offsets in days (default 0,30,90)")
    d.add_argument("--rounds", type=int, default=3, help="fuzz rounds per tool")
    d.add_argument("--timeout", type=float, default=4.0, help="seconds per tool/hook call")
    d.add_argument("--entry", action="append", default=[], help="catalog entry yaml to count as disclosure")
    d.add_argument("--allow-exec", action="store_true", help="let the plugin spawn processes in the chamber")
    d.add_argument("--keep", action="store_true", help="keep the chamber directory for inspection")
    d.add_argument("--json", action="store_true")
    d.add_argument("--ci", action="store_true", help="exit 2 on RED, 1 on AMBER")
    d.set_defaults(xray_func=cmd_detonate)

    v = sp.add_parser("verdicts", help="Latest verdict for every detonated plugin")
    v.set_defaults(xray_func=cmd_verdicts)

    s = sp.add_parser("show", help="Show a stored report card")
    s.add_argument("plugin"); s.add_argument("--sha"); s.add_argument("--json", action="store_true")
    s.set_defaults(xray_func=cmd_show)

    df = sp.add_parser("diff", help="Behaviour diff between two detonated versions")
    df.add_argument("plugin"); df.add_argument("old", nargs="?"); df.add_argument("new", nargs="?")
    df.add_argument("--ci", action="store_true", help="exit 1 when behaviour changed")
    df.set_defaults(xray_func=cmd_diff)

    ds = sp.add_parser("disclose", help="Draft the catalog disclosure line from observed behaviour")
    ds.add_argument("plugin"); ds.add_argument("--sha")
    ds.set_defaults(xray_func=cmd_disclose)

    b = sp.add_parser("bait", help="Plant / inspect / remove live decoy credential files (opt-in)")
    b.add_argument("action", choices=["plant", "status", "remove"])
    b.set_defaults(xray_func=cmd_bait)

    al = sp.add_parser("alerts", help="Runtime bait alerts")
    al.add_argument("--limit", type=int, default=20)
    al.set_defaults(xray_func=cmd_alerts)


def dispatch(args) -> int:
    fn = getattr(args, "xray_func", None)
    if fn is None:
        print(summary_text())
        return 0
    return int(fn(args) or 0)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="xray", description="Plugin X-Ray")
    setup_argparse(ap)
    return dispatch(ap.parse_args(argv))


if __name__ == "__main__":
    sys.exit(main())
