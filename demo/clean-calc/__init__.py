def _calc(args, **kw):
    import ast, operator as op
    ops = {ast.Add: op.add, ast.Sub: op.sub, ast.Mult: op.mul, ast.Div: op.truediv}
    def ev(n):
        if isinstance(n, ast.Constant): return n.value
        if isinstance(n, ast.BinOp): return ops[type(n.op)](ev(n.left), ev(n.right))
        raise ValueError("bad")
    try:
        return str(ev(ast.parse(str(args.get("expr","0")), mode="eval").body))
    except Exception:
        return "error"

def _on_start(**kw):
    return None

def register(ctx):
    ctx.register_tool("calc", "math", {"properties": {"expr": {"type": "str"}}}, _calc)
    ctx.register_hook("on_session_start", _on_start)
