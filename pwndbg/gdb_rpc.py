"""Localhost XML-RPC facade over a stopped GDB session, for the Julia REPL.

GDB's Python API is not thread-safe. Incoming RPC calls are received on worker
threads and then posted onto GDB's event loop with gdb.post_event.
"""

from __future__ import annotations

import os
import threading
from typing import Any, Callable

from ariadne_protocol.constants import DEFAULT_GDB_PORT, DEFAULT_HOST, MAX_MEMORY_TRANSFER
from ariadne_protocol.types import dumps_addr, loads_addr
from ariadne_protocol.xmlrpc_util import ThreadingXMLRPCServer


class GdbRpcServer:
    def __init__(self, gdb_mod, host: str | None = None, port: int | None = None) -> None:
        self.gdb = gdb_mod
        self.host = host or os.environ.get("ARIADNE_GDB_HOST", DEFAULT_HOST)
        self.port = int(port or os.environ.get("ARIADNE_GDB_PORT", DEFAULT_GDB_PORT))
        self._server: ThreadingXMLRPCServer | None = None
        self._thread: threading.Thread | None = None

    def start(self) -> str:
        if self._server is not None:
            return self.endpoint
        server = ThreadingXMLRPCServer(self.host, self.port)
        for name in (
            "ping",
            "read_memory",
            "write_memory",
            "registers",
            "pc",
            "breakpoints",
            "eval_expression",
        ):
            server.register_function(getattr(self, name), name)
        self._server = server
        thread = threading.Thread(target=server.serve_forever, name="ariadne-gdb-xmlrpc", daemon=True)
        self._thread = thread
        thread.start()
        return self.endpoint

    def stop(self) -> None:
        if self._server is not None:
            try:
                self._server.shutdown()
            except Exception:
                pass
            self._server = None

    @property
    def endpoint(self) -> str:
        return f"http://{self.host}:{self.port}/RPC2"

    def ping(self) -> dict[str, Any]:
        return {"ok": True, "endpoint": self.endpoint}

    def read_memory(self, addr: Any, size: int) -> bytes:
        n = int(size)
        if n < 0 or n > MAX_MEMORY_TRANSFER:
            raise ValueError(f"size must be 0..{MAX_MEMORY_TRANSFER}")
        address = loads_addr(addr)

        def job() -> bytes:
            inferior = self.gdb.selected_inferior()
            buf = inferior.read_memory(address, n)
            return bytes(buf)

        return self._on_gdb(job)

    def write_memory(self, addr: Any, data: bytes) -> dict[str, Any]:
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("data must be bytes")
        raw = bytes(data)
        if len(raw) > MAX_MEMORY_TRANSFER:
            raise ValueError(f"payload exceeds {MAX_MEMORY_TRANSFER} bytes")
        address = loads_addr(addr)

        def job() -> int:
            self.gdb.selected_inferior().write_memory(address, raw)
            return len(raw)

        written = self._on_gdb(job)
        return {"address": dumps_addr(address), "written": written}

    def registers(self) -> dict[str, str]:
        def job() -> dict[str, str]:
            frame = self.gdb.newest_frame()
            result: dict[str, str] = {}
            arch = frame.architecture()
            for name in arch.registers("general"):
                try:
                    value = int(frame.read_register(name))
                    result[str(name)] = hex(value)
                except Exception:
                    continue
            return result

        return self._on_gdb(job)

    def pc(self) -> str:
        def job() -> str:
            frame = self.gdb.newest_frame()
            return dumps_addr(int(frame.pc()))

        return self._on_gdb(job)

    def breakpoints(self) -> list[dict[str, Any]]:
        def job() -> list[dict[str, Any]]:
            out = []
            for bp in self.gdb.breakpoints() or []:
                loc = getattr(bp, "locations", None)
                addrs = []
                if loc:
                    for item in loc:
                        addr = getattr(item, "address", None)
                        if addr is not None:
                            addrs.append(int(addr))
                elif getattr(bp, "location", None):
                    try:
                        addrs.append(int(self.gdb.parse_and_eval(f"&*{bp.location}")))
                    except Exception:
                        pass
                for addr in addrs:
                    out.append(
                        {
                            "number": int(getattr(bp, "number", 0) or 0),
                            "address": dumps_addr(addr),
                            "enabled": bool(getattr(bp, "enabled", True)),
                            "extra": str(getattr(bp, "location", "") or ""),
                        }
                    )
            return out

        return self._on_gdb(job)

    def eval_expression(self, expression: str) -> str:
        """Evaluate a GDB expression and return its string form (read-only use)."""

        def job() -> str:
            value = self.gdb.parse_and_eval(expression)
            return str(value)

        return self._on_gdb(job)

    def _on_gdb(self, fn: Callable[[], Any]) -> Any:
        """Run `fn` on GDB's thread and block the RPC worker until it finishes."""
        done = threading.Event()
        box: dict[str, Any] = {}

        def wrapper() -> None:
            try:
                box["value"] = fn()
            except Exception as exc:  # propagate to the RPC thread
                box["error"] = exc
            finally:
                done.set()

        try:
            self.gdb.post_event(wrapper)
        except Exception:
            # Already on the GDB thread (e.g. tests / direct calls).
            return fn()
        if not done.wait(timeout=5.0):
            raise TimeoutError("GDB did not process the posted event in time")
        if "error" in box:
            raise box["error"]
        return box.get("value")
