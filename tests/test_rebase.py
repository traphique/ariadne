from ariadne_protocol.rebase import AddressMapper


def test_slide_zero_until_runtime_known() -> None:
    mapper = AddressMapper(analysis_base=0x400000)
    assert mapper.slide == 0
    assert not mapper.ready
    assert mapper.to_runtime(0x401000) == 0x401000


def test_aslr_roundtrip() -> None:
    mapper = AddressMapper(analysis_base=0x400000)
    mapper.set_runtime_base(0x555555554000)
    assert mapper.slide == 0x555555554000 - 0x400000
    runtime = mapper.to_runtime(0x401000)
    assert mapper.to_analysis(runtime) == 0x401000


def test_infer_from_entry_pair() -> None:
    mapper = AddressMapper(analysis_base=0x400000)
    mapper.infer_runtime_base(runtime_addr=0x555555555000, analysis_addr=0x401000)
    assert mapper.runtime_base == 0x555555554000
    assert mapper.to_analysis(0x555555555000) == 0x401000
