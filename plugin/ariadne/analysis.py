"""Read Binary Ninja analysis into protocol records.

These functions are intended to run off the UI thread. They only read analysis
state; they never touch UI widgets.
"""

from __future__ import annotations

from typing import Any, Iterable

from ariadne_protocol.types import (
    BasicBlockInfo,
    FunctionHeader,
    ILInstruction,
    StackVariable,
    StructMember,
    StructType,
    TypeDef,
)

_IL_ATTR = {
    "llil": "llil",
    "mlil": "mlil",
    "hlil": "hlil",
    "lifted_llil": "llil",
}


def _function_at(bv, addr: int):
    funcs = bv.get_functions_containing(addr)
    if funcs:
        return funcs[0]
    func = bv.get_function_at(addr)
    return func


def function_header(func) -> FunctionHeader:
    params: list[str] = []
    try:
        for var in func.parameter_vars:
            params.append(f"{var.type} {var.name}".strip())
    except Exception:
        params = []
    return_type = ""
    try:
        return_type = str(func.return_type) if func.return_type is not None else ""
    except Exception:
        return_type = ""
    type_string = ""
    try:
        type_string = str(func.type)
    except Exception:
        type_string = ""
    return FunctionHeader(
        start=int(func.start),
        name=str(func.name),
        type_string=type_string,
        parameters=params,
        return_type=return_type,
    )


def stack_variables(func) -> list[StackVariable]:
    result: list[StackVariable] = []
    seen: set[tuple[str, int]] = set()
    try:
        layout = list(func.stack_layout)
    except Exception:
        layout = []
    for var in layout:
        rec = _variable_record(var, default_source="stack")
        key = (rec.name, rec.offset)
        if key in seen:
            continue
        seen.add(key)
        result.append(rec)
    try:
        others = list(func.vars)
    except Exception:
        others = []
    for var in others:
        rec = _variable_record(var)
        key = (rec.name, rec.offset)
        if key in seen:
            continue
        seen.add(key)
        result.append(rec)
    result.sort(key=lambda v: (v.source != "stack", v.offset, v.name))
    return result


def _variable_record(var, default_source: str | None = None) -> StackVariable:
    source = default_source or "other"
    offset = 0
    try:
        src = str(getattr(var, "source_type", "") or "")
        if "Stack" in src:
            source = "stack"
            offset = int(var.storage)
        elif "Register" in src:
            source = "register"
            offset = int(getattr(var, "storage", 0) or 0)
        elif "Flag" in src:
            source = "flag"
            offset = int(getattr(var, "storage", 0) or 0)
        elif default_source == "stack":
            offset = int(getattr(var, "storage", 0) or 0)
    except Exception:
        pass
    size = 0
    type_name = ""
    try:
        if var.type is not None:
            type_name = str(var.type)
            size = int(getattr(var.type, "width", 0) or 0)
    except Exception:
        pass
    return StackVariable(
        name=str(getattr(var, "name", "") or ""),
        offset=offset,
        size=size,
        type_name=type_name,
        source=source,
    )


def basic_blocks(func) -> list[BasicBlockInfo]:
    blocks: list[BasicBlockInfo] = []
    try:
        raw = list(func.basic_blocks)
    except Exception:
        return blocks
    for block in raw:
        successors: list[int] = []
        try:
            for edge in block.outgoing_edges:
                target = getattr(edge, "target", None)
                if target is not None:
                    successors.append(int(target.start))
        except Exception:
            successors = []
        blocks.append(
            BasicBlockInfo(start=int(block.start), end=int(block.end), successors=successors)
        )
    return blocks


def il_instructions(func, level: str) -> list[ILInstruction]:
    attr = _IL_ATTR.get(level.lower())
    if attr is None:
        raise ValueError(f"unknown IL level {level!r}; expected llil, mlil, or hlil")
    il = getattr(func, attr, None)
    if il is None:
        return []
    out: list[ILInstruction] = []
    try:
        instructions = list(il.instructions)
    except Exception:
        return out
    for index, instr in enumerate(instructions):
        address = int(getattr(instr, "address", func.start) or func.start)
        operation = ""
        try:
            operation = str(getattr(instr, "operation", "") or "")
        except Exception:
            operation = ""
        out.append(
            ILInstruction(
                index=index,
                address=address,
                text=str(instr),
                operation=operation,
            )
        )
    return out


def export_types(bv) -> list[TypeDef]:
    exported: list[TypeDef] = []
    types: Iterable[Any]
    try:
        types = list(bv.types.items()) if hasattr(bv.types, "items") else list(bv.types)
    except Exception:
        return exported
    for item in types:
        if isinstance(item, tuple) and len(item) == 2:
            name, ty = item
        else:
            name, ty = getattr(item, "name", str(item)), item
        exported.append(type_def(str(name), ty))
    return exported


def export_type(bv, name: str) -> TypeDef | None:
    try:
        ty = bv.get_type_by_name(name)
    except Exception:
        ty = None
    if ty is None:
        return None
    return type_def(name, ty)


def type_def(name: str, ty) -> TypeDef:
    text = str(ty)
    kind = "other"
    struct = None
    try:
        structure = getattr(ty, "structure", None)
        if structure is not None:
            kind = "struct"
            members = []
            for member in getattr(structure, "members", []) or []:
                members.append(
                    StructMember(
                        name=str(getattr(member, "name", "")),
                        offset=int(getattr(member, "offset", 0) or 0),
                        type_name=str(getattr(member, "type", "") or ""),
                        size=int(getattr(getattr(member, "type", None), "width", 0) or 0),
                    )
                )
            struct = StructType(
                name=name,
                size=int(getattr(structure, "width", getattr(ty, "width", 0)) or 0),
                members=members,
            )
        elif "enum" in type(ty).__name__.lower() or str(getattr(ty, "type_class", "")).lower().find("enum") >= 0:
            kind = "enum"
        elif "typedef" in text.lower()[:16]:
            kind = "typedef"
    except Exception:
        pass
    return TypeDef(name=name, kind=kind, text=text, struct=struct)


def resolve_function(bv, addr: int):
    func = _function_at(bv, addr)
    if func is None:
        raise KeyError(f"no function contains address {addr:#x}")
    return func
