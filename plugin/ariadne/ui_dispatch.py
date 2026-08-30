"""Keep Binary Ninja's UI thread free during sync.

Rules:
- Never call execute_on_main_thread_and_wait from an RPC handler.
- UI mutations (highlight, navigate) are fire-and-forget on the main thread.
- Analysis reads run on the RPC/worker thread and are served from caches.
- PC updates are coalesced so a fast step loop does not queue highlight spam.
"""

from __future__ import annotations

from typing import Callable

from ariadne_protocol.cache import LatestValue

try:
    from binaryninja import execute_on_main_thread
except ImportError:  # headless unit tests
    execute_on_main_thread = None


class UIDispatcher:
    def __init__(self) -> None:
        self._pc = LatestValue()
        self._execute = execute_on_main_thread

    def set_executor(self, fn: Callable[[Callable[[], None]], None] | None) -> None:
        """Override for tests (inject a synchronous executor)."""
        self._execute = fn

    def run_ui(self, job: Callable[[], None]) -> None:
        """Schedule a short UI mutation. Never waits."""
        executor = self._execute
        if executor is None:
            job()
            return
        executor(job)

    def publish_pc(self, analysis_addr: int) -> int:
        return self._pc.publish(analysis_addr)

    def apply_if_latest_pc(self, seq: int, job: Callable[[int], None]) -> bool:
        value = self._pc.take_if_current(seq)
        if value is None:
            return False
        job(int(value))
        return True
