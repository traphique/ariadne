"""Background ThreadingXMLRPCServer hosted inside Binary Ninja."""

from __future__ import annotations

import os
import threading
from typing import Any

from ariadne_protocol.cache import StackVarCache
from ariadne_protocol.constants import DEFAULT_BN_PORT, DEFAULT_HOST
from ariadne_protocol.rebase import AddressMapper
from ariadne_protocol.xmlrpc_util import ThreadingXMLRPCServer

from .handlers import BridgeHandlers
from .highlight import HighlightController
from .notifications import UpdateLog
from .ui_dispatch import UIDispatcher

try:
    from binaryninja.log import log_error, log_info
except ImportError:
    def log_info(msg: str) -> None:
        print(msg)

    def log_error(msg: str) -> None:
        print(msg)


class BridgeServer:
    def __init__(self, host: str | None = None, port: int | None = None) -> None:
        self.host = host or os.environ.get("ARIADNE_BN_HOST", DEFAULT_HOST)
        self.port = int(port or os.environ.get("ARIADNE_BN_PORT", DEFAULT_BN_PORT))
        self.stack_cache = StackVarCache()
        self.updates = UpdateLog(self.stack_cache)
        self.dispatcher = UIDispatcher()
        self.highlights = HighlightController(self.dispatcher)
        self.mapper = AddressMapper(analysis_base=0)
        self.handlers = BridgeHandlers(
            self.stack_cache, self.updates, self.highlights, self.mapper
        )
        self._server: ThreadingXMLRPCServer | None = None
        self._thread: threading.Thread | None = None
        self._bv = None
        self._registered = False

    def attach(self, bv) -> None:
        if self._bv is not None and self._bv is not bv:
            try:
                self._bv.unregister_notification(self.updates)
            except Exception:
                pass
            self._registered = False
        self._bv = bv
        self.handlers.attach(bv)
        if not self._registered:
            try:
                bv.register_notification(self.updates)
                self._registered = True
            except Exception as exc:
                log_error(f"Ariadne could not register notifications: {exc}")

    def start(self) -> str:
        if self._server is not None:
            return self.endpoint
        server = ThreadingXMLRPCServer(self.host, self.port)
        for name in (
            "ping",
            "set_runtime_base",
            "infer_runtime_base",
            "get_function",
            "get_stack_vars",
            "get_basic_blocks",
            "get_il",
            "get_types",
            "get_type",
            "get_types_c_header",
            "get_updates",
            "set_pc",
            "set_breakpoints",
            "cache_stats",
        ):
            server.register_function(getattr(self.handlers, name), name)
        self._server = server
        thread = threading.Thread(
            target=self._serve, name="ariadne-xmlrpc", daemon=True
        )
        self._thread = thread
        thread.start()
        log_info(f"Ariadne XML-RPC server on {self.endpoint} (UI thread is not blocked)")
        return self.endpoint

    def _serve(self) -> None:
        assert self._server is not None
        try:
            self._server.serve_forever(poll_interval=0.25)
        except Exception as exc:
            log_error(f"Ariadne server stopped: {exc}")

    def stop(self) -> None:
        server = self._server
        self._server = None
        if server is not None:
            try:
                server.shutdown()
            except Exception:
                pass
            try:
                server.server_close()
            except Exception:
                pass
        if self._bv is not None and self._registered:
            try:
                self._bv.unregister_notification(self.updates)
            except Exception:
                pass
            self._registered = False

    @property
    def endpoint(self) -> str:
        return f"http://{self.host}:{self.port}/RPC2"

    @property
    def running(self) -> bool:
        return self._server is not None and self._thread is not None and self._thread.is_alive()

    def status_text(self) -> str:
        state = "running" if self.running else "stopped"
        filename = ""
        if self._bv is not None and getattr(self._bv, "file", None) is not None:
            filename = str(self._bv.file.filename)
        stats = self.stack_cache.stats.to_rpc()
        return (
            f"Ariadne {state} at {self.endpoint} file={filename!r} "
            f"seq={self.updates.seq} cache={stats}"
        )

    def status(self) -> dict[str, Any]:
        return {
            "running": self.running,
            "endpoint": self.endpoint,
            "seq": self.updates.seq,
            "cache": self.stack_cache.stats.to_rpc(),
        }
