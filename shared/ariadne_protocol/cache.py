"""Function-scoped stack-variable cache.

Stepping in GDB queries the same function's layout hundreds of times. Recalculating
Binary Ninja stack offsets on every stop is wasted work; this cache is the
hot path. Entries are invalidated when analysis reports that a function changed.
"""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass, field
from threading import RLock
from typing import Callable, Iterable

from .constants import STACK_CACHE_MAX_FUNCTIONS
from .types import StackVariable


@dataclass
class _Entry:
    revision: int
    variables: tuple[StackVariable, ...]
    hits: int = 0


@dataclass
class CacheStats:
    hits: int = 0
    misses: int = 0
    invalidations: int = 0
    evictions: int = 0

    def to_rpc(self) -> dict[str, int]:
        return {
            "hits": self.hits,
            "misses": self.misses,
            "invalidations": self.invalidations,
            "evictions": self.evictions,
        }


class StackVarCache:
    """Thread-safe LRU cache keyed by function start address."""

    def __init__(self, max_functions: int = STACK_CACHE_MAX_FUNCTIONS) -> None:
        if max_functions < 1:
            raise ValueError("max_functions must be >= 1")
        self._max = max_functions
        self._lock = RLock()
        self._entries: OrderedDict[int, _Entry] = OrderedDict()
        self._revisions: dict[int, int] = {}
        self.stats = CacheStats()

    def current_revision(self, func_start: int) -> int:
        with self._lock:
            return self._revisions.get(func_start, 0)

    def bump_revision(self, func_start: int) -> int:
        with self._lock:
            nxt = self._revisions.get(func_start, 0) + 1
            self._revisions[func_start] = nxt
            if func_start in self._entries:
                del self._entries[func_start]
                self.stats.invalidations += 1
            return nxt

    def invalidate(self, func_start: int) -> None:
        self.bump_revision(func_start)

    def invalidate_many(self, starts: Iterable[int]) -> None:
        for start in starts:
            self.invalidate(start)

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()
            self._revisions.clear()
            self.stats = CacheStats()

    def get(self, func_start: int) -> tuple[StackVariable, ...] | None:
        with self._lock:
            entry = self._entries.get(func_start)
            if entry is None:
                self.stats.misses += 1
                return None
            if entry.revision != self._revisions.get(func_start, 0):
                del self._entries[func_start]
                self.stats.misses += 1
                self.stats.invalidations += 1
                return None
            self._entries.move_to_end(func_start)
            entry.hits += 1
            self.stats.hits += 1
            return entry.variables

    def put(self, func_start: int, variables: Iterable[StackVariable]) -> tuple[StackVariable, ...]:
        frozen = tuple(variables)
        with self._lock:
            revision = self._revisions.setdefault(func_start, 0)
            self._entries[func_start] = _Entry(revision=revision, variables=frozen)
            self._entries.move_to_end(func_start)
            self._evict_unlocked()
            return frozen

    def get_or_load(
        self,
        func_start: int,
        loader: Callable[[], Iterable[StackVariable]],
    ) -> tuple[StackVariable, ...]:
        cached = self.get(func_start)
        if cached is not None:
            return cached
        loaded = tuple(loader())
        return self.put(func_start, loaded)

    def _evict_unlocked(self) -> None:
        while len(self._entries) > self._max:
            self._entries.popitem(last=False)
            self.stats.evictions += 1


@dataclass
class LatestValue:
    """Keep only the newest value (used to coalesce PC highlight jobs)."""

    _lock: RLock = field(default_factory=RLock, repr=False)
    _seq: int = 0
    _value: object | None = None

    def publish(self, value: object) -> int:
        with self._lock:
            self._seq += 1
            self._value = value
            return self._seq

    def take_if_current(self, seq: int) -> object | None:
        with self._lock:
            if seq != self._seq:
                return None
            return self._value
