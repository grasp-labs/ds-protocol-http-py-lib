"""
**File:** ``test_page_number.py``
**Region:** ``tests/dataset/pagination/strategies/test_page_number``

Unit tests for page-number pagination strategy.
"""

from __future__ import annotations

from ds_protocol_http_py_lib.dataset.pagination import (
    PageNumberPaginationSettings,
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


def test_page_number_inject_and_total_pages() -> None:
    """Page-number injects page/size and stops on the last 1-based page."""
    settings = PaginationSettings(
        strategy=PaginationStrategy.PAGE_NUMBER,
        page_number=PageNumberPaginationSettings(
            page_param="page",
            page_size_param="per_page",
            page_size=100,
            start_page=1,
            total_pages_path="total_pages",
        ),
    )
    cfg = settings.strategy_config
    strategy = get_strategy(PaginationStrategy.PAGE_NUMBER)
    state = strategy.initial_state(cfg, None)
    injected = strategy.inject(_base_request(), state, cfg)
    assert injected.params == {"q": "x", "page": 1, "per_page": 100}

    body = {"data": [{"id": 1}] * 100, "total_pages": 1}
    assert strategy.should_stop(
        body=body,
        headers={},
        items=body["data"],
        state=state,
        cfg=cfg,
    )


def test_page_number_total_pages_respects_start_page() -> None:
    """total_pages is a count; last ordinal is start_page + total_pages - 1."""
    items = [{"id": 1}] * 100
    body = {"data": items, "total_pages": 3}
    strategy = get_strategy(PaginationStrategy.PAGE_NUMBER)

    def _walk(start_page: int) -> list[tuple[int, bool]]:
        cfg = PageNumberPaginationSettings(
            page_size=100,
            start_page=start_page,
            total_pages_path="total_pages",
        )
        state = strategy.initial_state(cfg, None)
        seen: list[tuple[int, bool]] = []
        for _ in range(5):
            stopped = strategy.should_stop(
                body=body,
                headers={},
                items=items,
                state=state,
                cfg=cfg,
            )
            seen.append((state.values["page"], stopped))
            if stopped:
                break
            state = strategy.advance(
                body=body,
                headers={},
                items=items,
                state=state,
                cfg=cfg,
            )
        return seen

    assert _walk(1) == [(1, False), (2, False), (3, True)]
    assert _walk(0) == [(0, False), (1, False), (2, True)]


def test_page_number_resumes_from_checkpoint() -> None:
    """initial_state restores page/size/index via from_checkpoint."""
    settings = PaginationSettings(
        strategy=PaginationStrategy.PAGE_NUMBER,
        page_number=PageNumberPaginationSettings(page_size=50, start_page=1),
    )
    cfg = settings.strategy_config
    strategy = get_strategy(PaginationStrategy.PAGE_NUMBER)
    restored = strategy.initial_state(
        cfg,
        {"strategy": "page_number", "page": 3, "page_size": 50, "page_index": 2},
    )
    assert restored.values == {"page": 3, "page_size": 50}
    assert restored.page_index == 2
    assert (
        strategy.from_checkpoint(
            {"page": 4, "page_size": 50, "page_index": 3},
        ).values["page"]
        == 4
    )
