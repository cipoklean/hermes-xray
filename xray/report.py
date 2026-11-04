"""Human-readable report card for a detonation verdict, plus machine JSON."""

from __future__ import annotations

import json
from typing import Dict

_MARK = {"RED": "⛔ RED", "AMBER": "⚠️  AMBER", "GREEN": "✅ GREEN"}


def render(plugin: str, res: dict, *, width: int = 72) -> str:
    bar = "─" * width
    lines = [bar, f"  Plugin X-Ray · detonation report", f"  {plugin}", bar,
             f"  VERDICT: {_MARK.get(res['verdict'], res['verdict'])}",
             f"  fingerprint: {res['fingerprint']['hash']}", ""]
    if res["reasons"]:
        lines.append("  Why it's flagged:")
        lines += [f"    • {r}" for r in res["reasons"]]
        lines.append("")
    if res["amber"]:
        lines.append("  Also worth knowing:")
        lines += [f"    • {a}" for a in res["amber"]]
        lines.append("")
    lines.append("  Behaviour:")
    lines.append(f"    hosts    : {', '.join(res['hosts']) or '(none)'}")
    lines.append(f"    commands : {', '.join(res['commands']) or '(none)'}")
    lines.append(f"    writes   : {', '.join(res['writes']) or '(none)'}")
    lines.append(f"    reads    : {', '.join(res['reads']) or '(none)'}")
    if res["warp_only"]:
        lines.append("    ⏰ time-bomb: behaviour appeared only after the clock was advanced")
    lines.append("")
    if res["bait_hits"]:
        lines.append("  Honeytoken trips (proof, not guesswork):")
        for b in res["bait_hits"][:8]:
            when = f"+{b['warp_days']}d" if b.get("warp_days") else "day 0"
            if b["kind"] == "read":
                what = f"read   {b.get('bait')}"
            else:
                from .analysis import _host_of
                dest = _host_of(b["kind"], b["target"]) or b["target"][:40]
                what = f"leak   honeytoken → {dest}"
            lines.append(f"    • {what:38} {b['where']}  [{when}, {b.get('phase')}]")
        lines.append("")
    if res.get("sanctioned"):
        lines.append("  Credential use through the sanctioned path (OK):")
        lines += [f"    ✓ {x['note']}" for x in res["sanctioned"][:4]]
        lines.append("")
    lines.append("  " + res["disclosure"])
    lines.append(bar)
    return "\n".join(lines)


def to_json(plugin: str, res: dict, sha: str = "") -> str:
    return json.dumps({"plugin": plugin, "sha": sha, "verdict": res["verdict"],
                       "reasons": res["reasons"], "amber": res["amber"],
                       "fingerprint": res["fingerprint"], "hosts": res["hosts"],
                       "commands": res["commands"], "writes": res["writes"],
                       "reads": res["reads"], "warp_only": res["warp_only"],
                       "disclosure": res["disclosure"]}, indent=2)
