from apply_symbols import apply_function, gdb_ident, write_types_header
from ariadne_protocol.types import FunctionHeader, StructMember, StructType, TypeDef


class _Gdb:
    def __init__(self) -> None:
        self.commands: list[str] = []

    def execute(self, cmd: str, to_string: bool = False) -> str:  # noqa: ARG002
        self.commands.append(cmd)
        return ""


def test_gdb_ident_sanitizes() -> None:
    assert gdb_ident("main") == "main"
    assert gdb_ident("operator+") == "operator_"
    assert gdb_ident("0start") == "ari_0start"


def test_apply_function_sets_convenience_var() -> None:
    gdb = _Gdb()
    header = FunctionHeader(0x401000, "main", "int main(void)", [], "int")
    name = apply_function(gdb, header, 0x555555555000)
    assert name == "$ari_main"
    assert any("0x555555555000" in cmd for cmd in gdb.commands)


def test_write_types_header(tmp_path) -> None:
    path = write_types_header(
        [
            TypeDef(
                "node",
                "struct",
                "struct node",
                StructType("node", 8, [StructMember("v", 0, "int32_t", 4)]),
            )
        ],
        tmp_path / "types.h",
    )
    text = path.read_text(encoding="utf-8")
    assert "struct node" in text
    assert "int32_t v;" in text
