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
from ds_protocol_http_py_lib.dataset.pagination.inject import RequestSnapshot
from ds_protocol_http_py_lib.enums import HttpMethod


def _base_request() -> RequestSnapshot:
    return RequestSnapshot(
        url="https://api.example.com/items",
        method=HttpMethod.GET,
        params={"q": "x"},
    )


def test_offset_inject_advance_stop_and_checkpoint() -> None:
    """Offset injects params, advances by limit, stops on short page, round-trips checkpoint."""
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

    short = {"data": [{"id": 3}], "meta": {"total": 5}}
    assert strategy.should_stop(
        body=short,
        headers={},
        items=short["data"],
        state=nxt,
        cfg=cfg,
    )


def test_offset_stops_when_total_reached() -> None:
    """Offset terminates when offset + limit covers total."""
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
