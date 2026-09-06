"""
**File:** ``test_cursor.py``
**Region:** ``tests/dataset/pagination/strategies/test_cursor``

Unit tests for cursor / token pagination strategy.
"""

from __future__ import annotations

import pytest

from ds_protocol_http_py_lib.dataset.pagination import (
    CursorPaginationSettings,
    ExtractSource,
    InjectLocation,
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


def test_cursor_first_page_omits_cursor_then_echoes() -> None:
    """First cursor page omits the token; later pages echo the opaque value."""
    settings = PaginationSettings(
        strategy=PaginationStrategy.CURSOR,
        items_path="items",
        cursor=CursorPaginationSettings(
            cursor_path="response_metadata.next_cursor",
            cursor_source=ExtractSource.BODY,
            cursor_param="cursor",
            page_size_param="limit",
            page_size=200,
        ),
    )
    cfg = settings.strategy_config
    strategy = get_strategy(PaginationStrategy.CURSOR)
    state = strategy.initial_state(cfg, None)
    first = strategy.inject(_base_request(), state, cfg)
    assert "cursor" not in (first.params or {})
    assert first.params == {"q": "x", "limit": 200}

    body = {
        "items": [{"id": "a"}],
        "response_metadata": {"next_cursor": "tok-1"},
    }
    assert not strategy.should_stop(
        body=body,
        headers={},
        items=body["items"],
        state=state,
        cfg=cfg,
    )
    nxt = strategy.advance(
        body=body,
        headers={},
        items=body["items"],
        state=state,
        cfg=cfg,
    )
    second = strategy.inject(_base_request(), nxt, cfg)
    assert second.params["cursor"] == "tok-1"

    terminal = {
        "items": [{"id": "b"}],
        "response_metadata": {"next_cursor": ""},
    }
    assert strategy.should_stop(
        body=terminal,
        headers={},
        items=terminal["items"],
        state=nxt,
        cfg=cfg,
    )


def test_cursor_header_source_and_no_progress() -> None:
    """Header-carried cursors are supported; identical tokens raise."""
    settings = PaginationSettings(
        strategy=PaginationStrategy.CURSOR,
        cursor=CursorPaginationSettings(
            cursor_path="x-ms-continuation",
            cursor_source=ExtractSource.HEADER,
            cursor_param="x-ms-continuation",
            cursor_location=InjectLocation.HEADER,
        ),
    )
    cfg = settings.strategy_config
    strategy = get_strategy(PaginationStrategy.CURSOR)
    state = strategy.initial_state(cfg, None)
    state.values["cursor"] = "same"
    with pytest.raises(ValueError, match="no progress"):
        strategy.advance(
            body={},
            headers={"x-ms-continuation": "same"},
            items=[{"id": 1}],
            state=state,
            cfg=cfg,
        )
