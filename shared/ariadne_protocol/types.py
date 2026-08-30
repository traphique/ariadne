"""Serializable protocol records.

XML-RPC can only carry primitives, arrays, and structs (dicts). These helpers
convert dataclasses to/from that subset. 64-bit addresses are hex strings so
they survive XML-RPC's 32-bit <int> type.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Iterable, Mapping

from .constants import ADDR_PREFIX


def dumps_addr(addr: int) -> str:
    if addr < 0:
        raise ValueError(f"address must be non-negative, got {addr}")
    return f"{ADDR_PREFIX}{addr:x}"


def loads_addr(value: Any) -> int:
    if isinstance(value, bool):
        raise TypeError("boolean is not an address")
    if isinstance(value, int):
        return int(value)
    if isinstance(value, str):
        text = value.strip()
        if text.startswith(("0x", "0X")):
            return int(text, 16)
        return int(text, 0) if text[:1] == "0" else int(text, 10)
    raise TypeError(f"cannot parse address from {type(value).__name__}")


def _as_rpc(obj: Any) -> Any:
    if hasattr(obj, "to_rpc"):
        return obj.to_rpc()
    if isinstance(obj, dict):
        return {str(k): _as_rpc(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_as_rpc(v) for v in obj]
    return obj


@dataclass(frozen=True)
class StackVariable:
    name: str
    offset: int
    size: int
    type_name: str
    source: str  # "stack" | "register" | "flag"

    def to_rpc(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "offset": int(self.offset),
            "size": int(self.size),
            "type_name": self.type_name,
            "source": self.source,
        }

    @classmethod
    def from_rpc(cls, data: Mapping[str, Any]) -> "StackVariable":
        return cls(
            name=str(data["name"]),
            offset=int(data["offset"]),
            size=int(data.get("size", 0)),
            type_name=str(data.get("type_name", "")),
            source=str(data.get("source", "stack")),
        )


@dataclass(frozen=True)
class FunctionHeader:
    start: int
    name: str
    type_string: str
    parameters: list[str] = field(default_factory=list)
    return_type: str = ""

    def to_rpc(self) -> dict[str, Any]:
        return {
            "start": dumps_addr(self.start),
            "name": self.name,
            "type_string": self.type_string,
            "parameters": list(self.parameters),
            "return_type": self.return_type,
        }

    @classmethod
    def from_rpc(cls, data: Mapping[str, Any]) -> "FunctionHeader":
        return cls(
            start=loads_addr(data["start"]),
            name=str(data["name"]),
            type_string=str(data.get("type_string", "")),
            parameters=[str(p) for p in data.get("parameters", [])],
            return_type=str(data.get("return_type", "")),
        )


@dataclass(frozen=True)
class BasicBlockInfo:
    start: int
    end: int
    successors: list[int] = field(default_factory=list)

    def to_rpc(self) -> dict[str, Any]:
        return {
            "start": dumps_addr(self.start),
            "end": dumps_addr(self.end),
            "successors": [dumps_addr(s) for s in self.successors],
        }

    @classmethod
    def from_rpc(cls, data: Mapping[str, Any]) -> "BasicBlockInfo":
        return cls(
            start=loads_addr(data["start"]),
            end=loads_addr(data["end"]),
            successors=[loads_addr(s) for s in data.get("successors", [])],
        )


@dataclass(frozen=True)
class ILInstruction:
    index: int
    address: int
    text: str
    operation: str = ""

    def to_rpc(self) -> dict[str, Any]:
        return {
            "index": int(self.index),
            "address": dumps_addr(self.address),
            "text": self.text,
            "operation": self.operation,
        }

    @classmethod
    def from_rpc(cls, data: Mapping[str, Any]) -> "ILInstruction":
        return cls(
            index=int(data["index"]),
            address=loads_addr(data["address"]),
            text=str(data.get("text", "")),
            operation=str(data.get("operation", "")),
        )


@dataclass(frozen=True)
class StructMember:
    name: str
    offset: int
    type_name: str
    size: int = 0

    def to_rpc(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_rpc(cls, data: Mapping[str, Any]) -> "StructMember":
        return cls(
            name=str(data["name"]),
            offset=int(data["offset"]),
            type_name=str(data.get("type_name", "")),
            size=int(data.get("size", 0)),
        )


@dataclass(frozen=True)
class StructType:
    name: str
    size: int
    members: list[StructMember] = field(default_factory=list)

    def to_rpc(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "size": int(self.size),
            "members": [m.to_rpc() for m in self.members],
        }

    @classmethod
    def from_rpc(cls, data: Mapping[str, Any]) -> "StructType":
        members = [StructMember.from_rpc(m) for m in data.get("members", [])]
        return cls(name=str(data["name"]), size=int(data.get("size", 0)), members=members)


@dataclass(frozen=True)
class TypeDef:
    name: str
    kind: str  # "struct" | "enum" | "typedef" | "other"
    text: str
    struct: StructType | None = None

    def to_rpc(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "name": self.name,
            "kind": self.kind,
            "text": self.text,
        }
        if self.struct is not None:
            payload["struct"] = self.struct.to_rpc()
        return payload

    @classmethod
    def from_rpc(cls, data: Mapping[str, Any]) -> "TypeDef":
        struct = None
        if "struct" in data and data["struct"]:
            struct = StructType.from_rpc(data["struct"])
        return cls(
            name=str(data["name"]),
            kind=str(data.get("kind", "other")),
            text=str(data.get("text", "")),
            struct=struct,
        )


@dataclass(frozen=True)
class BreakpointInfo:
    number: int
    address: int
    enabled: bool
    extra: str = ""

    def to_rpc(self) -> dict[str, Any]:
        return {
            "number": int(self.number),
            "address": dumps_addr(self.address),
            "enabled": bool(self.enabled),
            "extra": self.extra,
        }

    @classmethod
    def from_rpc(cls, data: Mapping[str, Any]) -> "BreakpointInfo":
        return cls(
            number=int(data["number"]),
            address=loads_addr(data["address"]),
            enabled=bool(data.get("enabled", True)),
            extra=str(data.get("extra", "")),
        )


@dataclass
class SyncUpdate:
    """Incremental BN -> debugger delta, keyed by a monotonic sequence."""

    seq: int
    functions: list[FunctionHeader] = field(default_factory=list)
    types: list[TypeDef] = field(default_factory=list)
    stack_vars: dict[str, list[StackVariable]] = field(default_factory=dict)

    def to_rpc(self) -> dict[str, Any]:
        return {
            "seq": int(self.seq),
            "functions": [f.to_rpc() for f in self.functions],
            "types": [t.to_rpc() for t in self.types],
            "stack_vars": {
                start: [v.to_rpc() for v in vars_]
                for start, vars_ in self.stack_vars.items()
            },
        }

    @classmethod
    def from_rpc(cls, data: Mapping[str, Any]) -> "SyncUpdate":
        stack_vars: dict[str, list[StackVariable]] = {}
        raw_stack = data.get("stack_vars") or {}
        for start, vars_ in raw_stack.items():
            stack_vars[str(start)] = [StackVariable.from_rpc(v) for v in vars_]
        return cls(
            seq=int(data.get("seq", 0)),
            functions=[FunctionHeader.from_rpc(f) for f in data.get("functions", [])],
            types=[TypeDef.from_rpc(t) for t in data.get("types", [])],
            stack_vars=stack_vars,
        )


def rpc_list(items: Iterable[Any]) -> list[Any]:
    return [_as_rpc(item) for item in items]
