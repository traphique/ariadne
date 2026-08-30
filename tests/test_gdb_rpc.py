from __future__ import annotations

import threading

from gdb_rpc import GdbRpcServer
from ariadne_protocol.constants import MAX_MEMORY_TRANSFER


class _Arch:
    def registers(self, _group: str):
        return ["rip", "rsp"]


class _Frame:
    def architecture(self):
        return _Arch()

    def read_register(self, name: str) -> int:
        return {"rip": 0x555555555000, "rsp": 0x7FFFFFFFDE00}[name]

    def pc(self) -> int:
        return 0x555555555000


class _Location:
    address = 0x555555555140


class _Breakpoint:
    number = 1
    enabled = True
    location = "*0x555555555140"
    locations = [_Location()]


class _Inferior:
    def __init__(self) -> None:
        self.mem = bytearray(b"\x90" * 64)

    def read_memory(self, addr: int, size: int) -> memoryview:
        offset = addr & 0x3F
        return memoryview(self.mem[offset : offset + size])

    def write_memory(self, addr: int, data: bytes) -> None:
        offset = addr & 0x3F
        self.mem[offset : offset + len(data)] = data


class _FakeGdb:
    def __init__(self) -> None:
        self.inferior = _Inferior()

    def selected_inferior(self):
        return self.inferior

    def newest_frame(self):
        return _Frame()

    def breakpoints(self):
        return [_Breakpoint()]

    def parse_and_eval(self, expression: str):
        if expression == "$pc":
            return 0x555555555000
        return expression

    def post_event(self, fn) -> None:
        fn()


def test_gdb_rpc_memory_and_pc() -> None:
    gdb = _FakeGdb()
    rpc = GdbRpcServer(gdb, host="127.0.0.1", port=0)
    # Don't start the network server; call methods directly.
    assert rpc.pc() == "0x555555555000"
    regs = rpc.registers()
    assert regs["rip"] == "0x555555555000"
    blob = rpc.read_memory("0x555555555000", 4)
    assert blob == b"\x90\x90\x90\x90"
    rpc.write_memory("0x555555555000", b"\xcc\xcc")
    assert rpc.read_memory("0x555555555000", 2) == b"\xcc\xcc"
    bps = rpc.breakpoints()
    assert bps[0]["address"] == "0x555555555140"


def test_gdb_rpc_rejects_huge_read() -> None:
    rpc = GdbRpcServer(_FakeGdb())
    try:
        rpc.read_memory("0x0", MAX_MEMORY_TRANSFER + 1)
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_gdb_rpc_posts_to_gdb_thread() -> None:
    gdb = _FakeGdb()
    ran = threading.Event()

    def post(fn) -> None:
        ran.set()
        fn()

    gdb.post_event = post  # type: ignore[method-assign]
    rpc = GdbRpcServer(gdb)
    assert rpc.pc() == "0x555555555000"
    assert ran.is_set()
