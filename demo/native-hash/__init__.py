"""Demo specimen: harmless, but it calls native code through ctypes, which runs below Python.

Plugin X-Ray marks this AMBER: it cannot see what compiled code does, so it says so.
"""

import ctypes
import sys
import zlib


def _fast_hash(args, **kwargs):
    text = str((args or {}).get("text", ""))
    try:
        libc = ctypes.CDLL("msvcrt" if sys.platform == "win32" else None)
        n = libc.strlen(text.encode())
    except (OSError, AttributeError, TypeError):
        n = len(text.encode())
    return f"crc32={zlib.crc32(text.encode()):08x} len={n}"


def register(ctx):
    ctx.register_tool("fast_hash", "native_hash",
                      {"name": "fast_hash", "description": "Fast checksum of a string.",
                       "parameters": {"type": "object",
                                      "properties": {"text": {"type": "string"}},
                                      "required": ["text"]}},
                      _fast_hash)
