from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SHARED = ROOT / "shared"
PLUGIN = ROOT / "plugin"
PWNDBG = ROOT / "pwndbg"

for path in (SHARED, PLUGIN, PWNDBG):
    text = str(path)
    if text not in sys.path:
        sys.path.insert(0, text)


class MockType:
    def __init__(self, text: str, width: int = 8, structure=None) -> None:
        self._text = text
        self.width = width
        self.structure = structure
        self.type_class = "struct" if structure is not None else "integer"

    def __str__(self) -> str:
        return self._text


class MockMember:
    def __init__(self, name: str, offset: int, type_name: str, size: int) -> None:
        self.name = name
        self.offset = offset
        self.type = MockType(type_name, width=size)


class MockStructure:
    def __init__(self, width: int, members: list[MockMember]) -> None:
        self.width = width
        self.members = members


class MockVar:
    def __init__(self, name: str, storage: int, source_type: str, type_name: str, size: int = 8) -> None:
        self.name = name
        self.storage = storage
        self.source_type = source_type
        self.type = MockType(type_name, width=size)


class MockEdge:
    def __init__(self, target_start: int) -> None:
        self.target = type("T", (), {"start": target_start})()


class MockBlock:
    def __init__(self, start: int, end: int, successors: list[int] | None = None) -> None:
        self.start = start
        self.end = end
        self.outgoing_edges = [MockEdge(s) for s in (successors or [])]


class MockILInstr:
    def __init__(self, address: int, text: str, operation: str = "HLIL_CALL") -> None:
        self.address = address
        self.operation = operation
        self._text = text

    def __str__(self) -> str:
        return self._text


class MockIL:
    def __init__(self, instructions: list[MockILInstr]) -> None:
        self.instructions = instructions


class MockFunc:
    def __init__(self, start: int, name: str, size: int = 0x80) -> None:
        self.start = start
        self.size = size
        self.name = name
        self.type = f"int64_t {name}(int32_t arg1)"
        self.return_type = "int64_t"
        self.parameter_vars = [MockVar("arg1", 0, "RegisterVariableSourceType", "int32_t", 4)]
        self.stack_layout = [
            MockVar("var_10", -0x10, "StackVariableSourceType", "int64_t", 8),
            MockVar("buf", -0x40, "StackVariableSourceType", "char[40]", 40),
        ]
        self.vars = list(self.stack_layout) + list(self.parameter_vars)
        self.basic_blocks = [
            MockBlock(start, start + 0x20, [start + 0x20]),
            MockBlock(start + 0x20, start + size, []),
        ]
        self.hlil = MockIL(
            [
                MockILInstr(start, "int64_t result", "HLIL_VAR_INIT"),
                MockILInstr(start + 4, "return result", "HLIL_RET"),
            ]
        )
        self.mlil = self.hlil
        self.llil = self.hlil
        self.highlights: dict[int, object] = {}

    def set_user_instr_highlight(self, addr: int, color) -> None:
        self.highlights[int(addr)] = color


class MockFile:
    filename = "/tmp/demo.bin"


class MockBV:
    def __init__(self, funcs: list[MockFunc] | None = None) -> None:
        self._funcs = funcs or [MockFunc(0x401000, "main")]
        self.start = 0x400000
        self.file = MockFile()
        self.view = "Linear"
        self.types = {
            "node": MockType(
                "struct node",
                width=16,
                structure=MockStructure(
                    16,
                    [
                        MockMember("value", 0, "int32_t", 4),
                        MockMember("next", 8, "struct node*", 8),
                    ],
                ),
            )
        }
        self.notifications: list[object] = []
        self.navigated: list[tuple[object, int]] = []

    def get_functions_containing(self, addr: int):
        return [f for f in self._funcs if f.start <= addr < f.start + f.size]

    def get_function_at(self, addr: int):
        for func in self._funcs:
            if func.start == addr:
                return func
        return None

    def get_type_by_name(self, name: str):
        return self.types.get(name)

    def register_notification(self, notification) -> None:
        self.notifications.append(notification)

    def unregister_notification(self, notification) -> None:
        if notification in self.notifications:
            self.notifications.remove(notification)

    def navigate(self, view, addr: int) -> None:
        self.navigated.append((view, addr))


@pytest.fixture
def mock_bv() -> MockBV:
    return MockBV()
