"""XML-RPC method table. All handlers return XML-RPC-safe values quickly."""

from __future__ import annotations

from typing import Any

from ariadne_protocol.cache import StackVarCache
from ariadne_protocol.constants import PROTOCOL_VERSION
from ariadne_protocol.rebase import AddressMapper
from ariadne_protocol.types import dumps_addr, loads_addr

from . import analysis
from .c_types import types_to_c_header
from .highlight import HighlightController
from .notifications import UpdateLog


class BridgeHandlers:
    def __init__(
        self,
        stack_cache: StackVarCache,
        updates: UpdateLog,
        highlights: HighlightController,
        mapper: AddressMapper,
    ) -> None:
        self._bv = None
        self.stack_cache = stack_cache
        self.updates = updates
        self.highlights = highlights
        self.mapper = mapper

    def attach(self, bv) -> None:
        self._bv = bv
        self.highlights.attach(bv)
        try:
            self.mapper.analysis_base = int(bv.start)
        except Exception:
            pass

    def _require_bv(self):
        if self._bv is None:
            raise RuntimeError("Ariadne has no BinaryView; use Plugins → Ariadne → Start server")
        return self._bv

    def ping(self) -> dict[str, Any]:
        bv = self._bv
        return {
            "ok": True,
            "protocol": PROTOCOL_VERSION,
            "filename": str(getattr(bv, "file", None) and bv.file.filename or ""),
            "analysis_base": dumps_addr(self.mapper.analysis_base),
            "seq": self.updates.seq,
            "cache": self.stack_cache.stats.to_rpc(),
        }

    def set_runtime_base(self, runtime_base: Any) -> dict[str, Any]:
        self.mapper.set_runtime_base(loads_addr(runtime_base))
        return self.mapper.to_rpc()

    def infer_runtime_base(self, runtime_addr: Any, analysis_addr: Any) -> dict[str, Any]:
        self.mapper.infer_runtime_base(loads_addr(runtime_addr), loads_addr(analysis_addr))
        return self.mapper.to_rpc()

    def get_function(self, addr: Any, as_runtime: bool = False) -> dict[str, Any] | None:
        bv = self._require_bv()
        analysis_addr = self._to_analysis(addr, as_runtime)
        try:
            func = analysis.resolve_function(bv, analysis_addr)
        except KeyError:
            return None
        header = analysis.function_header(func)
        variables = self.stack_cache.get_or_load(func.start, lambda: analysis.stack_variables(func))
        return {
            "header": header.to_rpc(),
            "stack_vars": [v.to_rpc() for v in variables],
        }

    def get_stack_vars(self, addr: Any, as_runtime: bool = False) -> list[dict[str, Any]]:
        bv = self._require_bv()
        analysis_addr = self._to_analysis(addr, as_runtime)
        func = analysis.resolve_function(bv, analysis_addr)
        variables = self.stack_cache.get_or_load(func.start, lambda: analysis.stack_variables(func))
        return [v.to_rpc() for v in variables]

    def get_basic_blocks(self, addr: Any, as_runtime: bool = False) -> list[dict[str, Any]]:
        bv = self._require_bv()
        func = analysis.resolve_function(bv, self._to_analysis(addr, as_runtime))
        return [b.to_rpc() for b in analysis.basic_blocks(func)]

    def get_il(self, addr: Any, level: str = "hlil", as_runtime: bool = False) -> list[dict[str, Any]]:
        bv = self._require_bv()
        func = analysis.resolve_function(bv, self._to_analysis(addr, as_runtime))
        return [ins.to_rpc() for ins in analysis.il_instructions(func, level)]

    def get_types(self) -> list[dict[str, Any]]:
        return [t.to_rpc() for t in analysis.export_types(self._require_bv())]

    def get_type(self, name: str) -> dict[str, Any] | None:
        rec = analysis.export_type(self._require_bv(), name)
        return rec.to_rpc() if rec else None

    def get_types_c_header(self) -> str:
        return types_to_c_header(analysis.export_types(self._require_bv()))

    def get_updates(self, since: int = 0) -> dict[str, Any]:
        update = self.updates.snapshot(
            int(since),
            header_fn=analysis.function_header,
            type_fn=lambda name, ty: analysis.type_def(name, ty) if ty is not None else analysis.export_type(self._require_bv(), name),
            stack_fn=analysis.stack_variables,
        )
        return update.to_rpc()

    def set_pc(self, addr: Any, navigate: bool = True, as_runtime: bool = True) -> dict[str, Any]:
        analysis_addr = self._to_analysis(addr, as_runtime)
        self.highlights.set_pc(analysis_addr, navigate=bool(navigate))
        return {"address": dumps_addr(analysis_addr)}

    def set_breakpoints(self, addresses: list[Any], as_runtime: bool = True) -> dict[str, Any]:
        addrs = [self._to_analysis(a, as_runtime) for a in addresses]
        self.highlights.set_breakpoints(addrs)
        return {"count": len(addrs), "addresses": [dumps_addr(a) for a in addrs]}

    def cache_stats(self) -> dict[str, Any]:
        return self.stack_cache.stats.to_rpc()

    def _to_analysis(self, addr: Any, as_runtime: bool) -> int:
        value = loads_addr(addr)
        if as_runtime and self.mapper.ready:
            return self.mapper.to_analysis(value)
        return value
