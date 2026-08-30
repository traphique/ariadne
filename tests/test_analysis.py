import pytest

from ariadne import analysis


def test_missing_function_raises(mock_bv) -> None:
    with pytest.raises(KeyError):
        analysis.resolve_function(mock_bv, 0xDEAD)


def test_unknown_il_level_raises(mock_bv) -> None:
    func = mock_bv._funcs[0]
    with pytest.raises(ValueError):
        analysis.il_instructions(func, "sil")


def test_function_header_fields(mock_bv) -> None:
    header = analysis.function_header(mock_bv._funcs[0])
    assert header.name == "main"
    assert header.start == 0x401000
    assert any("arg1" in p for p in header.parameters)


def test_stack_layout_offsets_are_signed(mock_bv) -> None:
    vars_ = analysis.stack_variables(mock_bv._funcs[0])
    by_name = {v.name: v for v in vars_}
    assert by_name["var_10"].offset == -0x10
    assert by_name["buf"].offset == -0x40
    assert by_name["var_10"].source == "stack"
