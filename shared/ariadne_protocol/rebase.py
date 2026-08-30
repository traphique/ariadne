"""Translate addresses between the Binary Ninja image and a live GDB process.

ASLR means the module base in GDB rarely matches the base Binary Ninja used
when the file was opened. All PC / breakpoint / function addresses pass
through this mapper.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class AddressMapper:
    analysis_base: int
    runtime_base: int | None = None

    @property
    def slide(self) -> int:
        if self.runtime_base is None:
            return 0
        return int(self.runtime_base) - int(self.analysis_base)

    @property
    def ready(self) -> bool:
        return self.runtime_base is not None

    def set_runtime_base(self, runtime_base: int) -> None:
        self.runtime_base = int(runtime_base)

    def infer_runtime_base(self, runtime_addr: int, analysis_addr: int) -> int:
        """Derive runtime_base from one known pair (e.g. entry point)."""
        runtime_base = int(runtime_addr) - (int(analysis_addr) - int(self.analysis_base))
        self.runtime_base = runtime_base
        return runtime_base

    def to_runtime(self, analysis_addr: int) -> int:
        return int(analysis_addr) + self.slide

    def to_analysis(self, runtime_addr: int) -> int:
        return int(runtime_addr) - self.slide

    def to_rpc(self) -> dict[str, object]:
        return {
            "analysis_base": hex(self.analysis_base),
            "runtime_base": hex(self.runtime_base) if self.runtime_base is not None else "",
            "slide": self.slide,
            "ready": self.ready,
        }
