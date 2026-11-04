"""Schema-derived fuzz inputs for a tool, and synthetic kwargs for each hook. Deterministic:
the same schema always yields the same rounds, so a detonation is reproducible.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List

_STR_VALUES = [
    "", "xray", "../../../xray-outside.txt", "https://xray-probe.invalid/collect",
    "A" * 5000, "'; DROP TABLE t; --", "\x00\x01\x02", "😀 unicode ☃",
    "http://127.0.0.1:9/x", "file:///xray-probe.txt",
]
_INT_VALUES = [0, 1, -1, 2 ** 31, 999999999]


def _one(prop: Dict[str, Any], rnd: int) -> Any:
    t = (prop or {}).get("type", "str")
    if "enum" in (prop or {}) and prop["enum"]:
        return prop["enum"][rnd % len(prop["enum"])]
    if "default" in (prop or {}) and rnd == 0:
        return prop["default"]
    if t in ("str", "string"):
        return _STR_VALUES[rnd % len(_STR_VALUES)]
    if t in ("int", "integer"):
        return _INT_VALUES[rnd % len(_INT_VALUES)]
    if t in ("float", "number"):
        return [0.0, 1.5, -1.0][rnd % 3]
    if t in ("bool", "boolean"):
        return rnd % 2 == 0
    if t in ("list", "array"):
        return [_one((prop or {}).get("items", {"type": "str"}), rnd)]
    if t in ("dict", "object"):
        return {"k": _STR_VALUES[rnd % len(_STR_VALUES)]}
    return _STR_VALUES[rnd % len(_STR_VALUES)]


def _properties(schema: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(schema, dict):
        return {}
    fn = schema.get("function") or {}
    params = (fn.get("parameters") or schema.get("parameters") or schema).get("properties") \
        if isinstance(fn, dict) else None
    if isinstance(params, dict):
        return params
    for key in ("properties", "parameters"):
        if isinstance(schema.get(key), dict):
            inner = schema[key]
            if isinstance(inner.get("properties"), dict):
                return inner["properties"]
            return inner
    return {}


def fuzz_args(schema: Dict[str, Any], rounds: int = 3) -> List[Dict[str, Any]]:
    props = _properties(schema)
    out = []
    for r in range(max(1, rounds)):
        out.append({name: _one(prop, r) for name, prop in props.items()} if props else {})
    return out


def synthetic_hook_kwargs(hook: str) -> Dict[str, Any]:
    base = {"session_id": "xray-sess", "task_id": "xray-task", "model": "nous/hermes-4",
            "platform": "cli"}
    if hook == "pre_tool_call":
        return dict(base, tool_name="shell_exec", args={"command": "echo hi"})
    if hook == "post_tool_call":
        return dict(base, tool_name="shell_exec", args={"command": "echo hi"},
                    result="hi", duration_ms=3)
    if hook == "pre_llm_call":
        return dict(base, user_message="hello", conversation_history=[], is_first_turn=True)
    if hook == "post_llm_call":
        return dict(base, user_message="hello", assistant_response="hi",
                    conversation_history=[])
    if hook in ("on_session_start", "on_session_end", "on_session_reset", "on_session_finalize"):
        return dict(base, completed=True, interrupted=False)
    if hook == "post_compaction":
        return dict(base, old_session_id="old", kind="auto", reason="size")
    return dict(base)
