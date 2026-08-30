"""Shared Ariadne protocol types, caches, and helpers.

This package is imported by the Binary Ninja plugin and the pwndbg client.
It has no Binary Ninja or GDB imports so it can be unit-tested headlessly.
"""

from .c_types import types_to_c_header
from .cache import StackVarCache
from .constants import DEFAULT_BN_PORT, DEFAULT_GDB_PORT, DEFAULT_HOST, PROTOCOL_VERSION
from .rebase import AddressMapper
from .types import (
    BasicBlockInfo,
    BreakpointInfo,
    FunctionHeader,
    ILInstruction,
    StackVariable,
    StructMember,
    StructType,
    SyncUpdate,
    TypeDef,
    dumps_addr,
    loads_addr,
)

__all__ = [
    "AddressMapper",
    "BasicBlockInfo",
    "BreakpointInfo",
    "DEFAULT_BN_PORT",
    "DEFAULT_GDB_PORT",
    "DEFAULT_HOST",
    "FunctionHeader",
    "ILInstruction",
    "PROTOCOL_VERSION",
    "StackVarCache",
    "StackVariable",
    "StructMember",
    "StructType",
    "SyncUpdate",
    "TypeDef",
    "dumps_addr",
    "loads_addr",
    "types_to_c_header",
]
