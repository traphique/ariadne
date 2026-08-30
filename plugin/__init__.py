"""Binary Ninja entry point for Ariadne.

Binary Ninja imports this module at startup. Plugin commands start/stop the
localhost XML-RPC server without blocking the UI thread.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Allow `import ariadne_protocol` whether the plugin is a symlink or a copy.
_REPO_SHARED = Path(__file__).resolve().parent.parent / "shared"
if _REPO_SHARED.is_dir() and str(_REPO_SHARED) not in sys.path:
    sys.path.insert(0, str(_REPO_SHARED))

from binaryninja import PluginCommand  # noqa: E402
from binaryninja.log import log_error, log_info  # noqa: E402

from ariadne.server import BridgeServer  # noqa: E402

_SERVER: BridgeServer | None = None


def _server() -> BridgeServer:
    global _SERVER
    if _SERVER is None:
        _SERVER = BridgeServer()
    return _SERVER


def start_bridge(bv) -> None:
    try:
        _server().attach(bv)
        endpoint = _server().start()
        log_info(f"Ariadne listening on {endpoint}")
    except Exception as exc:
        log_error(f"Ariadne failed to start: {exc}")
        raise


def stop_bridge(bv) -> None:  # noqa: ARG001
    if _SERVER is None:
        return
    _SERVER.stop()
    log_info("Ariadne stopped")


def status_bridge(bv) -> None:  # noqa: ARG001
    srv = _server()
    log_info(srv.status_text())


PluginCommand.register(
    "Ariadne\\Start server",
    "Start the localhost XML-RPC server for GDB/pwndbg and Julia",
    start_bridge,
)
PluginCommand.register(
    "Ariadne\\Stop server",
    "Stop the Ariadne XML-RPC server",
    stop_bridge,
)
PluginCommand.register(
    "Ariadne\\Status",
    "Print Ariadne server status to the log",
    status_bridge,
)
