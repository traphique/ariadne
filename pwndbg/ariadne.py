"""pwndbg / GDB client for Ariadne.

Source this file from GDB after pwndbg has loaded:

    (gdb) source /path/to/ariadne/pwndbg/ariadne.py
    (gdb) ariadne-connect
    (gdb) ariadne-base 0x555555554000

On every stop the client:
  1. Pushes the current PC and breakpoint list to Binary Ninja (highlight).
  2. Pulls pending rename / type / stack-var updates and applies them locally.
Stack-variable offsets are cached per function so stepping does not re-query BN.
"""

from __future__ import annotations

import os
import sys
import threading
from pathlib import Path

# Make the shared protocol importable regardless of how this file is sourced.
_ROOT = Path(__file__).resolve().parent.parent
_SHARED = _ROOT / "shared"
if str(_SHARED) not in sys.path:
    sys.path.insert(0, str(_SHARED))
if str(Path(__file__).resolve().parent) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parent))

import gdb  # type: ignore  # noqa: E402

from apply_symbols import apply_functions, apply_types  # noqa: E402
from ariadne_protocol.cache import StackVarCache  # noqa: E402
from ariadne_protocol.constants import DEFAULT_BN_PORT, DEFAULT_HOST  # noqa: E402
from ariadne_protocol.rebase import AddressMapper  # noqa: E402
from ariadne_protocol.types import FunctionHeader, SyncUpdate, dumps_addr, loads_addr  # noqa: E402
from ariadne_protocol.xmlrpc_util import make_proxy, port_open  # noqa: E402
from gdb_rpc import GdbRpcServer  # noqa: E402


class BridgeClient:
    def __init__(self) -> None:
        self.host = os.environ.get("ARIADNE_BN_HOST", DEFAULT_HOST)
        self.port = int(os.environ.get("ARIADNE_BN_PORT", DEFAULT_BN_PORT))
        self.proxy = None
        self.mapper = AddressMapper(analysis_base=0)
        self.stack_cache = StackVarCache()
        self.last_seq = 0
        self._last_func_start: int | None = None
        self.gdb_rpc = GdbRpcServer(gdb)
        self._lock = threading.Lock()
        self._hooked = False
        self.enabled = True

    def connect(self, host: str | None = None, port: int | None = None) -> str:
        if host:
            self.host = host
        if port:
            self.port = int(port)
        if not port_open(self.host, self.port):
            raise ConnectionError(
                f"Binary Ninja is not listening on {self.host}:{self.port}. "
                "In BN: Plugins → Ariadne → Start server"
            )
        self.proxy = make_proxy(self.host, self.port, timeout=2.0)
        hello = self.proxy.ping()
        try:
            self.mapper.analysis_base = loads_addr(hello.get("analysis_base", "0x0"))
        except Exception:
            pass
        self.last_seq = int(hello.get("seq", 0) or 0)
        self.gdb_rpc.start()
        self._install_hooks()
        return f"connected to {self.host}:{self.port} (BN seq={self.last_seq})"

    def _install_hooks(self) -> None:
        if self._hooked:
            return
        gdb.events.stop.connect(self._on_stop)
        gdb.events.cont.connect(self._on_cont)
        for name in ("breakpoint_created", "breakpoint_deleted", "breakpoint_modified"):
            registry = getattr(gdb.events, name, None)
            if registry is not None:
                registry.connect(self._on_breakpoint_change)
        self._try_pwndbg_hooks()
        self._hooked = True

    def _try_pwndbg_hooks(self) -> None:
        try:
            import pwndbg

            event_handler = getattr(pwndbg.dbg, "event_handler", None)
            event_type = getattr(pwndbg, "dbg_mod", None)
            if event_handler is None or event_type is None:
                return

            @event_handler(event_type.EventType.STOP)
            def _pwndbg_stop(*_args) -> None:
                self._on_stop(None)

        except Exception:
            return

    def _on_stop(self, event) -> None:  # noqa: ARG002
        if not self.enabled or self.proxy is None:
            return
        # Do not call gdb.execute here — that can deadlock GDB/pwndbg on stop.
        thread = threading.Thread(target=self._sync_stop, name="ariadne-stop", daemon=True)
        thread.start()

    def _on_cont(self, event) -> None:  # noqa: ARG002
        return

    def _on_breakpoint_change(self, event) -> None:  # noqa: ARG002
        if not self.enabled or self.proxy is None:
            return
        threading.Thread(target=self._push_breakpoints, name="ariadne-bp", daemon=True).start()

    def _sync_stop(self) -> None:
        with self._lock:
            try:
                self._push_pc()
                self._push_breakpoints()
                self._pull_updates()
                self._warm_stack_cache()
            except Exception as exc:
                gdb.post_event(lambda: gdb.write(f"[ariadne] sync failed: {exc}\n"))

    def _current_pc(self) -> int:
        frame = gdb.newest_frame()
        return int(frame.pc())

    def _push_pc(self) -> None:
        assert self.proxy is not None
        pc = self._current_pc()
        self.proxy.set_pc(dumps_addr(pc), True, True)

    def _breakpoint_addresses(self) -> list[str]:
        addrs: list[str] = []
        for bp in gdb.breakpoints() or []:
            if not getattr(bp, "enabled", True):
                continue
            locations = getattr(bp, "locations", None)
            if locations:
                for loc in locations:
                    addr = getattr(loc, "address", None)
                    if addr is not None:
                        addrs.append(dumps_addr(int(addr)))
        return addrs

    def _push_breakpoints(self) -> None:
        assert self.proxy is not None
        self.proxy.set_breakpoints(self._breakpoint_addresses(), True)

    def _pull_updates(self) -> None:
        assert self.proxy is not None
        raw = self.proxy.get_updates(int(self.last_seq))
        update = SyncUpdate.from_rpc(raw)
        if update.seq <= self.last_seq and not update.functions and not update.types:
            return
        self.last_seq = update.seq

        def apply() -> None:
            if update.functions:
                apply_functions(gdb, update.functions, self.mapper.to_runtime)
            if update.types:
                apply_types(gdb, update.types, compile_debug=False)
            for start, variables in update.stack_vars.items():
                try:
                    self.stack_cache.put(loads_addr(start), variables)
                except Exception:
                    continue

        gdb.post_event(apply)

    def sync_now(self) -> str:
        if self.proxy is None:
            return "not connected"
        self._sync_stop()
        return f"synced (seq={self.last_seq})"

    def set_runtime_base(self, runtime_base: int) -> str:
        self.mapper.set_runtime_base(int(runtime_base))
        if self.proxy is not None:
            self.proxy.set_runtime_base(dumps_addr(int(runtime_base)))
        return f"slide={self.mapper.slide:#x}"

    def infer_base_from_pc(self, analysis_addr: int) -> str:
        runtime = self._current_pc()
        self.mapper.infer_runtime_base(runtime, int(analysis_addr))
        if self.proxy is not None:
            self.proxy.infer_runtime_base(dumps_addr(runtime), dumps_addr(int(analysis_addr)))
        return f"runtime_base={self.mapper.runtime_base:#x} slide={self.mapper.slide:#x}"

    def _warm_stack_cache(self) -> None:
        """Resolve the function containing $pc. Layout is cached per function start."""
        if self.proxy is None:
            return
        pc = self._current_pc()
        analysis_pc = self.mapper.to_analysis(pc) if self.mapper.ready else pc
        raw = self.proxy.get_function(dumps_addr(analysis_pc), False)
        if not raw:
            self._last_func_start = None
            return
        header = FunctionHeader.from_rpc(raw["header"])
        from ariadne_protocol.types import StackVariable

        variables = [StackVariable.from_rpc(v) for v in raw.get("stack_vars", [])]
        self.stack_cache.put(header.start, variables)
        self._last_func_start = header.start

    def stack_vars_at_pc(self) -> list[dict]:
        if self.proxy is None:
            raise RuntimeError("not connected")
        if self._last_func_start is not None:
            cached = self.stack_cache.get(self._last_func_start)
            if cached is not None:
                return [v.to_rpc() for v in cached]
        self._warm_stack_cache()
        if self._last_func_start is None:
            return []
        cached = self.stack_cache.get(self._last_func_start)
        return [v.to_rpc() for v in cached] if cached is not None else []


CLIENT = BridgeClient()


class _Command(gdb.Command):
    def __init__(self, name: str, invoke) -> None:
        super().__init__(name, gdb.COMMAND_USER)
        self._invoke = invoke

    def invoke(self, arg: str, from_tty: bool) -> None:  # noqa: ARG002
        self._invoke(gdb.string_to_argv(arg))


def _cmd_connect(args: list[str]) -> None:
    host = args[0] if args else None
    port = int(args[1]) if len(args) > 1 else None
    gdb.write(CLIENT.connect(host, port) + "\n")


def _cmd_status(_args: list[str]) -> None:
    gdb.write(
        f"enabled={CLIENT.enabled} proxy={CLIENT.proxy is not None} "
        f"seq={CLIENT.last_seq} {CLIENT.mapper.to_rpc()} "
        f"cache={CLIENT.stack_cache.stats.to_rpc()} "
        f"gdb_rpc={CLIENT.gdb_rpc.endpoint}\n"
    )


def _cmd_sync(_args: list[str]) -> None:
    gdb.write(CLIENT.sync_now() + "\n")


def _cmd_base(args: list[str]) -> None:
    if not args:
        gdb.write("usage: ariadne-base <runtime-base>|pc <analysis-addr>\n")
        return
    if args[0] == "pc":
        if len(args) < 2:
            gdb.write("usage: ariadne-base pc <analysis-addr>\n")
            return
        gdb.write(CLIENT.infer_base_from_pc(int(args[1], 0)) + "\n")
        return
    gdb.write(CLIENT.set_runtime_base(int(args[0], 0)) + "\n")


def _cmd_stack(_args: list[str]) -> None:
    for var in CLIENT.stack_vars_at_pc():
        gdb.write(
            f"  {var['source']:8} {var['offset']:+#x}  {var['type_name']} {var['name']}\n"
        )


def _cmd_enable(args: list[str]) -> None:
    CLIENT.enabled = not (args and args[0] in {"0", "off", "false"})
    gdb.write(f"ariadne enabled={CLIENT.enabled}\n")


_Command("ariadne-connect", _cmd_connect)
_Command("ariadne", _cmd_status)
_Command("ariadne-sync", _cmd_sync)
_Command("ariadne-base", _cmd_base)
_Command("ariadne-stack", _cmd_stack)
_Command("ariadne-enable", _cmd_enable)

gdb.write("[ariadne] loaded. Run `ariadne-connect` after starting the BN plugin.\n")
