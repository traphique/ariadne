from ariadne_protocol.cache import LatestValue, StackVarCache
from ariadne_protocol.types import StackVariable


def _var(name: str, offset: int) -> StackVariable:
    return StackVariable(name, offset, 8, "int64_t", "stack")


def test_miss_then_hit_and_stats() -> None:
    cache = StackVarCache(max_functions=8)
    assert cache.get(0x401000) is None
    cache.put(0x401000, [_var("var_10", -16)])
    hit = cache.get(0x401000)
    assert hit is not None
    assert hit[0].name == "var_10"
    assert cache.stats.misses == 1
    assert cache.stats.hits == 1


def test_invalidate_forces_reload() -> None:
    cache = StackVarCache()
    cache.put(0x401000, [_var("old", -8)])
    cache.invalidate(0x401000)
    assert cache.get(0x401000) is None
    cache.put(0x401000, [_var("renamed", -8)])
    hit = cache.get(0x401000)
    assert hit is not None and hit[0].name == "renamed"
    assert cache.stats.invalidations >= 1


def test_get_or_load_calls_loader_once() -> None:
    cache = StackVarCache()
    calls = {"n": 0}

    def loader():
        calls["n"] += 1
        return [_var("x", -0x20)]

    first = cache.get_or_load(0x401000, loader)
    second = cache.get_or_load(0x401000, loader)
    assert first == second
    assert calls["n"] == 1


def test_lru_eviction() -> None:
    cache = StackVarCache(max_functions=2)
    cache.put(1, [_var("a", -8)])
    cache.put(2, [_var("b", -8)])
    cache.put(3, [_var("c", -8)])
    assert cache.get(1) is None
    assert cache.get(2) is not None
    assert cache.get(3) is not None
    assert cache.stats.evictions == 1


def test_latest_value_drops_stale() -> None:
    box = LatestValue()
    first = box.publish(0x401000)
    second = box.publish(0x401004)
    assert box.take_if_current(first) is None
    assert box.take_if_current(second) == 0x401004
