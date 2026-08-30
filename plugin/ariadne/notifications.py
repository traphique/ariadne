"""Track Binary Ninja analysis edits as a monotonic update log.

The pwndbg client polls `get_updates(since)` on stop instead of walking the
entire symbol table after every step.
"""

from __future__ import annotations

from threading import RLock
from typing import Any

from ariadne_protocol.cache import StackVarCache
from ariadne_protocol.types import FunctionHeader, SyncUpdate, TypeDef

try:
    from binaryninja.binaryview import BinaryDataNotification
    from binaryninja.enums import NotificationType
except ImportError:  # unit tests
    class BinaryDataNotification:  # type: ignore[no-redef]
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            pass

    class NotificationType:  # type: ignore[no-redef]
        FunctionUpdated = 0
        FunctionAdded = 0
        FunctionRemoved = 0
        TypeDefined = 0
        TypeUndefined = 0
        SymbolUpdated = 0
        SymbolAdded = 0
        SymbolRemoved = 0


class UpdateLog(BinaryDataNotification):
    def __init__(self, stack_cache: StackVarCache) -> None:
        try:
            super().__init__(
                NotificationType.FunctionUpdated
                | NotificationType.FunctionAdded
                | NotificationType.FunctionRemoved
                | getattr(NotificationType, "TypeDefined", 0)
                | getattr(NotificationType, "TypeUndefined", 0)
                | getattr(NotificationType, "SymbolUpdated", 0)
                | getattr(NotificationType, "SymbolAdded", 0)
                | getattr(NotificationType, "SymbolRemoved", 0)
            )
        except TypeError:
            super().__init__()
        self._lock = RLock()
        self._seq = 0
        self._functions: dict[int, tuple[int, Any]] = {}
        self._types: dict[str, tuple[int, Any]] = {}
        self.stack_cache = stack_cache

    @property
    def seq(self) -> int:
        with self._lock:
            return self._seq

    def _next_seq(self) -> int:
        self._seq += 1
        return self._seq

    def note_function(self, func) -> int:
        with self._lock:
            seq = self._next_seq()
            self._functions[int(func.start)] = (seq, func)
            self.stack_cache.invalidate(int(func.start))
            return seq

    def note_type(self, name: str, ty=None) -> int:
        with self._lock:
            seq = self._next_seq()
            self._types[str(name)] = (seq, ty)
            return seq

    def function_added(self, view, func) -> None:  # noqa: ARG002
        self.note_function(func)

    def function_updated(self, view, func) -> None:  # noqa: ARG002
        self.note_function(func)

    def function_removed(self, view, func) -> None:  # noqa: ARG002
        self.note_function(func)

    def type_defined(self, view, name, ty) -> None:  # noqa: ARG002
        self.note_type(str(name), ty)

    def type_undefined(self, view, name, ty) -> None:  # noqa: ARG002
        self.note_type(str(name), ty)

    def symbol_added(self, view, sym) -> None:  # noqa: ARG002
        self._touch_symbol(sym)

    def symbol_updated(self, view, sym) -> None:  # noqa: ARG002
        self._touch_symbol(sym)

    def symbol_removed(self, view, sym) -> None:  # noqa: ARG002
        self._touch_symbol(sym)

    def _touch_symbol(self, sym) -> None:
        addr = int(getattr(sym, "address", 0) or 0)
        if addr:
            self.stack_cache.invalidate(addr)
            with self._lock:
                self._next_seq()

    def snapshot(self, since: int, header_fn, type_fn, stack_fn) -> SyncUpdate:
        """Collect records with seq > since. Callers supply extractors so this
        module stays independent of Binary Ninja type details."""
        with self._lock:
            current = self._seq
            funcs = [(addr, func) for addr, (seq, func) in self._functions.items() if seq > since]
            types = [(name, ty) for name, (seq, ty) in self._types.items() if seq > since]
            # Drop consumed entries so the log does not grow without bound.
            self._functions = {a: v for a, v in self._functions.items() if v[0] > since}
            self._types = {n: v for n, v in self._types.items() if v[0] > since}

        headers: list[FunctionHeader] = []
        stack_vars: dict[str, list] = {}
        for addr, func in funcs:
            try:
                headers.append(header_fn(func))
                stack_vars[hex(int(addr))] = list(stack_fn(func))
            except Exception:
                continue
        typedefs: list[TypeDef] = []
        for name, ty in types:
            try:
                rec = type_fn(name, ty)
                if rec is not None:
                    typedefs.append(rec)
            except Exception:
                continue
        return SyncUpdate(seq=current, functions=headers, types=typedefs, stack_vars=stack_vars)
