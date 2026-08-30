from ariadne_protocol.types import (
    FunctionHeader,
    ILInstruction,
    StackVariable,
    StructMember,
    StructType,
    SyncUpdate,
    TypeDef,
    dumps_addr,
    loads_addr,
)


def test_addr_hex_roundtrip() -> None:
    for addr in (0, 1, 0x401000, 0x7FFFFFFFFFFF, (1 << 64) - 1):
        assert loads_addr(dumps_addr(addr)) == addr


def test_loads_addr_accepts_int_and_hex() -> None:
    assert loads_addr(0x401000) == 0x401000
    assert loads_addr("0x401000") == 0x401000
    assert loads_addr("4194304") == 4194304


def test_dumps_addr_rejects_negative() -> None:
    try:
        dumps_addr(-1)
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_function_header_rpc_uses_hex_start() -> None:
    header = FunctionHeader(0x401000, "main", "int main(void)", ["void"], "int")
    raw = header.to_rpc()
    assert raw["start"] == "0x401000"
    assert FunctionHeader.from_rpc(raw) == header


def test_sync_update_roundtrip() -> None:
    update = SyncUpdate(
        seq=7,
        functions=[FunctionHeader(0x401000, "main", "void main()", [], "void")],
        types=[
            TypeDef(
                "node",
                "struct",
                "struct node",
                StructType("node", 16, [StructMember("value", 0, "int32_t", 4)]),
            )
        ],
        stack_vars={"0x401000": [StackVariable("var_10", -16, 8, "int64_t", "stack")]},
    )
    again = SyncUpdate.from_rpc(update.to_rpc())
    assert again.seq == 7
    assert again.functions[0].name == "main"
    assert again.types[0].struct is not None
    assert again.types[0].struct.members[0].name == "value"
    assert again.stack_vars["0x401000"][0].offset == -16


def test_il_instruction_roundtrip() -> None:
    instr = ILInstruction(3, 0x7FABC0000000, "rax = rdi", "HLIL_ASSIGN")
    assert ILInstruction.from_rpc(instr.to_rpc()) == instr
