"""Localhost-only XML-RPC helpers shared by the BN plugin and the GDB client."""

from __future__ import annotations

import socket
from socketserver import ThreadingMixIn
from typing import Any, Callable
from xmlrpc.client import ServerProxy, Transport
from xmlrpc.server import SimpleXMLRPCRequestHandler, SimpleXMLRPCServer


class _QuietRequestHandler(SimpleXMLRPCRequestHandler):
    rpc_paths = ("/", "/RPC2")

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        return


class ThreadingXMLRPCServer(ThreadingMixIn, SimpleXMLRPCServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, host: str, port: int, allow_none: bool = True) -> None:
        if host not in ("127.0.0.1", "localhost", "::1"):
            raise ValueError(
                "Ariadne XML-RPC must bind to localhost "
                f"(got {host!r}); refusing a non-loopback bind"
            )
        super().__init__(
            (host, port),
            requestHandler=_QuietRequestHandler,
            allow_none=allow_none,
            logRequests=False,
            use_builtin_types=True,
        )
        self.register_introspection_functions()


class _TimeoutTransport(Transport):
    def __init__(self, timeout: float) -> None:
        super().__init__(use_builtin_types=True)
        self._timeout = timeout

    def make_connection(self, host: str):  # type: ignore[override]
        conn = super().make_connection(host)
        conn.timeout = self._timeout
        return conn


def make_proxy(host: str, port: int, timeout: float = 2.0) -> ServerProxy:
    return ServerProxy(
        f"http://{host}:{port}/RPC2",
        allow_none=True,
        use_builtin_types=True,
        transport=_TimeoutTransport(timeout),
    )


def register_namespace(server: SimpleXMLRPCServer, prefix: str, methods: dict[str, Callable[..., Any]]) -> None:
    for name, fn in methods.items():
        server.register_function(fn, f"{prefix}.{name}" if prefix else name)


def port_open(host: str, port: int, timeout: float = 0.2) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False
