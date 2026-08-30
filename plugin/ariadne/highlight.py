"""PC and breakpoint highlights in the decompiler / graph views.

All UI work is posted through UIDispatcher.run_ui so RPC threads never wait
on the main thread.
"""

from __future__ import annotations

from typing import Iterable

from .ui_dispatch import UIDispatcher

try:
    from binaryninja.enums import HighlightStandardColor
except ImportError:

    class HighlightStandardColor:  # type: ignore[no-redef]
        NoHighlightColor = 0
        RedHighlightColor = 1
        BlueHighlightColor = 2
        GreenHighlightColor = 3


_PC_COLOR = getattr(HighlightStandardColor, "RedHighlightColor", 1)
_BP_COLOR = getattr(HighlightStandardColor, "BlueHighlightColor", 2)
_CLEAR = getattr(HighlightStandardColor, "NoHighlightColor", 0)


class HighlightController:
    def __init__(self, dispatcher: UIDispatcher) -> None:
        self._ui = dispatcher
        self._last_pc: int | None = None
        self._last_breakpoints: set[int] = set()
        self._bv = None

    def attach(self, bv) -> None:
        self._bv = bv

    def set_pc(self, analysis_addr: int, navigate: bool = True) -> None:
        seq = self._ui.publish_pc(analysis_addr)
        bv = self._bv

        def ui_job() -> None:
            if bv is None:
                return
            # Drop this job if a newer PC was published while we were queued.
            self._ui.apply_if_latest_pc(seq, lambda addr: self._apply_pc(bv, addr, navigate))

        self._ui.run_ui(ui_job)

    def set_breakpoints(self, analysis_addrs: Iterable[int]) -> None:
        addrs = set(int(a) for a in analysis_addrs)
        bv = self._bv

        def ui_job() -> None:
            if bv is None:
                return
            self._apply_breakpoints(bv, addrs)

        self._ui.run_ui(ui_job)

    def _apply_pc(self, bv, addr: int, navigate: bool) -> None:
        if self._last_pc is not None and self._last_pc != addr:
            self._highlight_addr(bv, self._last_pc, _CLEAR)
        self._highlight_addr(bv, addr, _PC_COLOR)
        self._last_pc = addr
        if navigate:
            self._navigate(bv, addr)

    def _apply_breakpoints(self, bv, addrs: set[int]) -> None:
        removed = self._last_breakpoints - addrs
        for old in removed:
            if old != self._last_pc:
                self._highlight_addr(bv, old, _CLEAR)
        for bp in addrs:
            if bp != self._last_pc:
                self._highlight_addr(bv, bp, _BP_COLOR)
        self._last_breakpoints = addrs

    def _highlight_addr(self, bv, addr: int, color) -> None:
        try:
            funcs = bv.get_functions_containing(addr)
        except Exception:
            return
        for func in funcs:
            try:
                func.set_user_instr_highlight(addr, color)
            except Exception:
                continue

    def _navigate(self, bv, addr: int) -> None:
        try:
            from binaryninjaui import UIContext

            ctx = UIContext.activeContext()
            if ctx is not None:
                frame = ctx.getCurrentViewFrame()
                if frame is not None:
                    for view_name in ("High Level IL", "Linear:High Level IL", bv.view):
                        try:
                            if frame.navigate(view_name, addr):
                                return
                        except Exception:
                            continue
        except Exception:
            pass
        try:
            bv.navigate(getattr(bv, "view", None) or "Linear", addr)
        except Exception:
            pass
