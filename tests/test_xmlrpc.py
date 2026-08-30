from __future__ import annotations

import threading

from xmlrpc.client import ServerProxy

from ariadne_protocol.cache import StackVarCache
from ariadne_protocol.rebase import AddressMapper
from ariadne_protocol.xmlrpc_util import ThreadingXMLRPCServer
from ariadne.handlers import BridgeHandlers
from ariadne.highlight import HighlightController
from ariadne.notifications import UpdateLog
from ariadne.ui_dispatch import UIDispatcher


def test_xmlrpc_refuses_non_loopback() -> None:
    try:
        ThreadingXMLRPCServer("0.0.0.0", 19999)
    except ValueError as exc:
        assert "localhost" in str(exc)
        return
    raise AssertionError("expected ValueError")


def test_xmlrpc_roundtrip_64bit_and_nested_structs(mock_bv) -> None:
    cache = StackVarCache()
    updates = UpdateLog(cache)
    dispatcher = UIDispatcher()
    dispatcher.set_executor(lambda job: job())
    handlers = BridgeHandlers(
        cache, updates, HighlightController(dispatcher), AddressMapper(mock_bv.start)
    )
    handlers.attach(mock_bv)

    server = ThreadingXMLRPCServer("127.0.0.1", 0)
    port = server.server_address[1]
    for name in ("ping", "get_function", "get_il", "set_pc"):
        server.register_function(getattr(handlers, name), name)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        proxy = ServerProxy(f"http://127.0.0.1:{port}/RPC2", allow_none=True, use_builtin_types=True)
        hello = proxy.ping()
        assert hello["ok"] is True
        rec = proxy.get_function("0x401000", False)
        assert rec["header"]["name"] == "main"
        il = proxy.get_il("0x401000", "hlil", False)
        assert il[1]["text"] == "return result"
        proxy.set_pc("0x401000", True, False)
        assert 0x401000 in mock_bv._funcs[0].highlights
    finally:
        server.shutdown()
        server.server_close()
