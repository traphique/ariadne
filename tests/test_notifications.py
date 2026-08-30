from ariadne_protocol.cache import StackVarCache
from ariadne.analysis import function_header, stack_variables
from ariadne.notifications import UpdateLog


def test_update_log_is_incremental(mock_bv) -> None:
    cache = StackVarCache()
    log = UpdateLog(cache)
    first = mock_bv._funcs[0]
    log.note_function(first)
    snap = log.snapshot(0, function_header, lambda n, t: None, stack_variables)
    assert snap.seq == 1
    assert snap.functions[0].name == "main"
    assert "0x401000" in snap.stack_vars

    later = log.snapshot(snap.seq, function_header, lambda n, t: None, stack_variables)
    assert later.functions == []
    assert later.seq == snap.seq

    renamed = mock_bv._funcs[0]
    renamed.name = "entry"
    log.note_function(renamed)
    delta = log.snapshot(snap.seq, function_header, lambda n, t: None, stack_variables)
    assert delta.functions[0].name == "entry"
    assert cache.get(0x401000) is None
