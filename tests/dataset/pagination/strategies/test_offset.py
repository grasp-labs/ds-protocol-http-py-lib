"""
**File:** ``test_offset.py``
**Region:** ``tests/dataset/pagination/strategies/test_offset``

Unit tests for offset / limit pagination strategy.
"""

from __future__ import annotations

from ds_protocol_http_py_lib.dataset.pagination import (
    OffsetPaginationSettings,
    PaginationSettings,
    PaginationStrategy,
    get_strategy,
)
from ds_protocol_http_py_lib.enums import HttpMethod
from ds_protocol_http_py_lib.utils.http.request import RequestSnapshot


def _base_request() -> RequestSnapshot:
    return RequestSnapshot(
        url="https://api.example.com/items",
        method=HttpMethod.GET,
        params={"q": "x"},
    )


def test_offset_inject_advance_stop_and_checkpoint() -> None:
    """Offset injects params, advances by the rows returned, stops when they cover total, round-trips checkpoint."""
    settings = PaginationSettings(
        strategy=PaginationStrategy.OFFSET,
        items_path="data",
        offset=OffsetPaginationSettings(
            offset_param="offset",
            limit_param="limit",
            page_size=2,
            initial_offset=0,
            total_path="meta.total",
        ),
    )
    cfg = settings.strategy_config
    strategy = get_strategy(PaginationStrategy.OFFSET)
    state = strategy.initial_state(cfg, None)
    injected = strategy.inject(_base_request(), state, cfg)
    assert injected.params == {"q": "x", "offset": 0, "limit": 2}

    body = {"data": [{"id": 1}, {"id": 2}], "meta": {"total": 5}}
    assert not strategy.should_stop(
        body=body,
        headers={},
        items=body["data"],
        state=state,
        cfg=cfg,
    )
    nxt = strategy.advance(
        body=body,
        headers={},
        items=body["data"],
        state=state,
        cfg=cfg,
    )
    assert nxt.values["offset"] == 2
    ck = strategy.to_checkpoint(nxt)
    restored = strategy.from_checkpoint(ck)
    assert restored.values["offset"] == 2

    one = {"data": [{"id": 3}], "meta": {"total": 4}}
    assert not strategy.should_stop(
        body=one,
        headers={},
        items=one["data"],
        state=nxt,
        cfg=cfg,
    )
    last = strategy.advance(
        body=one,
        headers={},
        items=one["data"],
        state=nxt,
        cfg=cfg,
    )
    assert last.values == {"offset": 3, "limit": 2}
    covered = {"data": [{"id": 4}], "meta": {"total": 4}}
    assert strategy.should_stop(
        body=covered,
        headers={},
        items=covered["data"],
        state=last,
        cfg=cfg,
    )


def test_offset_short_page_continues_while_total_remains() -> None:
    """A short page continues while the rows received have not covered total.

    The next offset moves by those rows and the requested limit stays put.
    Stopping on length here drops the remaining rows. The same short page stops
    once the rows cover total, and when the total path is missing.
    """
    settings = PaginationSettings(
        strategy=PaginationStrategy.OFFSET,
        offset=OffsetPaginationSettings(page_size=2, total_path="meta.total"),
    )
    cfg = settings.strategy_config
    strategy = get_strategy(PaginationStrategy.OFFSET)
    state = strategy.initial_state(cfg, None)
    state.values["offset"] = 2

    short = {"data": [{"id": 3}], "meta": {"total": 5}}
    assert not strategy.should_stop(
        body=short,
        headers={},
        items=short["data"],
        state=state,
        cfg=cfg,
    )
    stepped = strategy.advance(
        body=short,
        headers={},
        items=short["data"],
        state=state,
        cfg=cfg,
    )
    assert stepped.values == {"offset": 3, "limit": 2}

    covered = {"data": [{"id": 5}], "meta": {"total": 5}}
    state.values["offset"] = 4
    assert strategy.should_stop(
        body=covered,
        headers={},
        items=covered["data"],
        state=state,
        cfg=cfg,
    )

    missing_total = {"data": [{"id": 3}]}
    state.values["offset"] = 2
    assert strategy.should_stop(
        body=missing_total,
        headers={},
        items=missing_total["data"],
        state=state,
        cfg=cfg,
    )


def test_offset_empty_page_stops_while_total_remains() -> None:
    """An empty page stops even when total says more rows exist."""
    settings = PaginationSettings(
        strategy=PaginationStrategy.OFFSET,
        offset=OffsetPaginationSettings(page_size=100, total_path="meta.total"),
    )
    cfg = settings.strategy_config
    strategy = get_strategy(PaginationStrategy.OFFSET)
    state = strategy.initial_state(cfg, None)

    assert strategy.should_stop(
        body={"data": [], "meta": {"total": 10000}},
        headers={},
        items=[],
        state=state,
        cfg=cfg,
    )


def test_offset_advance_preserves_checkpoint_limit() -> None:
    """Resume must keep checkpoint limit; cfg.page_size must not replace it after advance."""
    settings = PaginationSettings(
        strategy=PaginationStrategy.OFFSET,
        offset=OffsetPaginationSettings(page_size=50, initial_offset=0),
    )
    cfg = settings.strategy_config
    strategy = get_strategy(PaginationStrategy.OFFSET)
    state = strategy.initial_state(
        cfg,
        {"strategy": "offset", "offset": 20, "limit": 10, "page_index": 2},
    )
    items = [{"id": i} for i in range(10)]
    assert not strategy.should_stop(
        body={"data": items},
        headers={},
        items=items,
        state=state,
        cfg=cfg,
    )
    nxt = strategy.advance(
        body={"data": items},
        headers={},
        items=items,
        state=state,
        cfg=cfg,
    )
    assert nxt.values == {"offset": 30, "limit": 10}
    assert nxt.page_index == 3
    injected = strategy.inject(_base_request(), nxt, cfg)
    assert injected.params == {"q": "x", "offset": 30, "limit": 10}
    short = [{"id": 1}] * 9
    assert strategy.should_stop(
        body={"data": short},
        headers={},
        items=short,
        state=nxt,
        cfg=cfg,
    )


def test_offset_capped_page_steps_through_every_row() -> None:
    """A server cap below page_size steps by the rows returned.

    Requested limit stays 100. Each page returns 50 rows of a 200-row result.
    The read visits offsets 0, 50, 100, and 150, then stops. It does not jump
    to 100 after the first page, and it does not stop at offset 100 while
    rows 150-199 are still outstanding.
    """
    settings = PaginationSettings(
        strategy=PaginationStrategy.OFFSET,
        offset=OffsetPaginationSettings(page_size=100, total_path="meta.total"),
    )
    cfg = settings.strategy_config
    strategy = get_strategy(PaginationStrategy.OFFSET)
    state = strategy.initial_state(cfg, None)
    offsets: list[int] = []
    seen: list[int] = []
    for _ in range(5):
        offset = int(state.values["offset"])
        offsets.append(offset)
        count = min(50, 200 - offset)
        items = [{"id": i} for i in range(offset, offset + count)]
        body = {"data": items, "meta": {"total": 200}}
        if strategy.should_stop(body=body, headers={}, items=items, state=state, cfg=cfg):
            seen.extend(item["id"] for item in items)
            break
        seen.extend(item["id"] for item in items)
        state = strategy.advance(body=body, headers={}, items=items, state=state, cfg=cfg)
        assert state.values["limit"] == 100
        injected = strategy.inject(_base_request(), state, cfg)
        assert injected.params["limit"] == 100
    else:
        raise AssertionError(f"offset walk did not stop: {offsets}")

    assert offsets == [0, 50, 100, 150]
    assert seen == list(range(200))


def test_offset_stops_when_total_reached() -> None:
    """Offset terminates when the rows received cover total."""
    settings = PaginationSettings(
        strategy=PaginationStrategy.OFFSET,
        offset=OffsetPaginationSettings(page_size=50, total_path="meta.total"),
    )
    cfg = settings.strategy_config
    strategy = get_strategy(PaginationStrategy.OFFSET)
    state = strategy.initial_state(cfg, None)
    state.values["offset"] = 100
    body = {"data": [{"id": 1}] * 50, "meta": {"total": 137}}
    assert strategy.should_stop(
        body=body,
        headers={},
        items=body["data"],
        state=state,
        cfg=cfg,
    )
