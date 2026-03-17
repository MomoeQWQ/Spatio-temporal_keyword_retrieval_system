"""Optional native acceleration with transparent Python fallback."""

from __future__ import annotations

import os
from typing import Iterable, Sequence

try:
    from . import _native_accel as _impl  # type: ignore
    NATIVE_ACCEL_ENABLED = True
except Exception:
    _impl = None
    NATIVE_ACCEL_ENABLED = False

if _impl is None and os.name == "nt":
    _dll_dirs = [
        r"C:\Program Files\mingw64\bin",
        r"C:\msys64\mingw64\bin",
    ]
    for _d in _dll_dirs:
        if os.path.isdir(_d):
            try:
                os.add_dll_directory(_d)
            except Exception:
                pass
    try:
        from . import _native_accel as _impl  # type: ignore
        NATIVE_ACCEL_ENABLED = True
    except Exception:
        _impl = None
        NATIVE_ACCEL_ENABLED = False


def xor_bytes(a: bytes, b: bytes) -> bytes:
    if _impl is not None:
        return _impl.xor_bytes(a, b)
    return bytes(x ^ y for x, y in zip(a, b))


def xor_many(chunks: Iterable[bytes]) -> bytes:
    seq = list(chunks)
    if not seq:
        return b""
    if _impl is not None:
        return _impl.xor_many(seq)
    out = seq[0]
    for c in seq[1:]:
        out = xor_bytes(out, c)
    return out


def xor_pair_lists(left: Sequence[bytes], right: Sequence[bytes]) -> list[bytes]:
    if _impl is not None:
        return list(_impl.xor_pair_lists(left, right))
    return [xor_bytes(a, b) for a, b in zip(left, right)]
