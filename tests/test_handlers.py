from ariadne_protocol.cache import StackVarCache
from ariadne_protocol.rebase import AddressMapper
from ariadne.handlers import BridgeHandlers
from ariadne.highlight import HighlightController
from ariadne.notifications import UpdateLog
from ariadne.ui_dispatch import UIDispatcher


def _handlers(mock_bv):
    cache = StackVarCache()
    updates = UpdateLog(cache)
    dispatcher = UIDispatcher()
    dispatcher.set_executor(lambda job: job())
    highlights = HighlightController(dispatcher)
    mapper = AddressMapper(analysis_base=mock_bv.start)
    handlers = BridgeHandlers(cache, updates, highlights, mapper)
    handlers.attach(mock_bv)
    return handlers


def test_ping_and_function_query(mock_bv) -> None:
    handlers = _handlers(mock_bv)
    hello = handlers.ping()
    assert hello["ok"] is True
    assert hello["analysis_base"] == "0x400000"
    rec = handlers.get_function("0x401000", False)
    assert rec is not None
    assert rec["header"]["name"] == "main"
    assert rec["header"]["start"] == "0x401000"
    names = {v["name"] for v in rec["stack_vars"]}
    assert "var_10" in names
    assert "buf" in names


def test_stack_var_cache_hits_on_second_query(mock_bv) -> None:
    handlers = _handlers(mock_bv)
    handlers.get_stack_vars("0x401000", False)
    handlers.get_stack_vars("0x401004", False)
    stats = handlers.cache_stats()
    assert stats["hits"] >= 1
    assert stats["misses"] == 1


def test_basic_blocks_and_hlil(mock_bv) -> None:
    handlers = _handlers(mock_bv)
    blocks = handlers.get_basic_blocks("0x401000", False)
    assert len(blocks) == 2
    assert blocks[0]["start"] == "0x401000"
    il = handlers.get_il("0x401000", "hlil", False)
    assert il[0]["text"] == "int64_t result"
    assert il[0]["address"] == "0x401000"


def test_types_and_c_header(mock_bv) -> None:
    handlers = _handlers(mock_bv)
    types = handlers.get_types()
    assert any(t["name"] == "node" for t in types)
    header = handlers.get_types_c_header()
    assert "struct node" in header


def test_set_pc_highlights_and_navigates(mock_bv) -> None:
    handlers = _handlers(mock_bv)
    handlers.mapper.set_runtime_base(0x400000)
    handlers.set_pc("0x401004", True, True)
    func = mock_bv._funcs[0]
    assert 0x401004 in func.highlights
    assert mock_bv.navigated
    assert mock_bv.navigated[-1][1] == 0x401004


def test_set_pc_uses_slide_for_runtime_address(mock_bv) -> None:
    handlers = _handlers(mock_bv)
    handlers.set_runtime_base("0x555555554000")
    # analysis 0x401000 == runtime 0x555555555000
    handlers.set_pc("0x555555555000", True, True)
    func = mock_bv._funcs[0]
    assert 0x401000 in func.highlights


def test_pc_coalesce_keeps_latest_only(mock_bv) -> None:
    handlers = _handlers(mock_bv)
    queued: list = []
    handlers.highlights._ui.set_executor(queued.append)
    handlers.mapper.set_runtime_base(0x400000)
    handlers.set_pc("0x401000", False, True)
    handlers.set_pc("0x401010", False, True)
    assert len(queued) == 2
    queued[0]()  # stale
    queued[1]()
    func = mock_bv._funcs[0]
    assert 0x401010 in func.highlights
    # The stale job must not leave 0x401000 as the current PC highlight color
    # after the latest job ran (it may have been written then cleared).
    assert handlers.highlights._last_pc == 0x401010
