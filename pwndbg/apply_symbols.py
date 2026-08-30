"""Apply Binary Ninja names and types onto a live GDB session.

GDB cannot grow a full ELF symbol table at runtime, so function names become
convenience variables (`$ari_main`) plus `set $ari_names` documentation. Structs
are emitted as a C header that can optionally be compiled with debug info.
"""

from __future__ import annotations

import os
import re
import tempfile
from pathlib import Path

from ariadne_protocol.c_types import types_to_c_header
from ariadne_protocol.types import FunctionHeader, TypeDef

_IDENT = re.compile(r"[^A-Za-z0-9_]")


def gdb_ident(name: str) -> str:
    cleaned = _IDENT.sub("_", name)
    if not cleaned or cleaned[0].isdigit():
        cleaned = f"ari_{cleaned}"
    return cleaned


def apply_function(gdb_mod, header: FunctionHeader, runtime_addr: int) -> str:
    ident = gdb_ident(header.name)
    conv = f"$ari_{ident}"
    gdb_mod.execute(f"set {conv} = (void *) {runtime_addr:#x}", to_string=True)
    if header.type_string:
        gdb_mod.execute(
            f'set {conv}_type = "{_escape(header.type_string)}"',
            to_string=True,
        )
    return conv


def apply_functions(gdb_mod, headers: list[FunctionHeader], to_runtime) -> list[str]:
    names = []
    for header in headers:
        names.append(apply_function(gdb_mod, header, int(to_runtime(header.start))))
    return names


def write_types_header(types: list[TypeDef], path: Path | None = None) -> Path:
    if path is None:
        handle = tempfile.NamedTemporaryFile(
            prefix="ariadne_types_", suffix=".h", delete=False, mode="w", encoding="utf-8"
        )
        handle.write(types_to_c_header(types))
        handle.close()
        return Path(handle.name)
    path.write_text(types_to_c_header(types), encoding="utf-8")
    return path


def maybe_compile_types(header: Path) -> Path | None:
    """Best-effort: compile a dummy .o with debug info so GDB can `ptype` structs.

    Returns the object path on success, or None if a compiler is unavailable.
    """
    compiler = os.environ.get("ARIADNE_CC", "cc")
    source = header.with_suffix(".c")
    obj = header.with_suffix(".o")
    source.write_text(f'#include "{header.name}"\nstatic struct {{int _;}} _ariadne_anchor;\n', encoding="utf-8")
    import subprocess

    try:
        subprocess.run(
            [compiler, "-g", "-c", "-o", str(obj), str(source), f"-I{header.parent}"],
            check=True,
            capture_output=True,
            timeout=20,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return obj if obj.is_file() else None


def apply_types(gdb_mod, types: list[TypeDef], compile_debug: bool = True) -> dict[str, str]:
    header = write_types_header(types)
    result = {"header": str(header)}
    if compile_debug:
        obj = maybe_compile_types(header)
        if obj is not None:
            try:
                gdb_mod.execute(f"add-symbol-file {obj} 0", to_string=True)
                result["object"] = str(obj)
            except Exception:
                result["object"] = ""
    return result


def _escape(text: str) -> str:
    return text.replace("\\", "\\\\").replace('"', '\\"')
