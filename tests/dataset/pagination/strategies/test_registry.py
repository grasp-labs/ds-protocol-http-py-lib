"""
**File:** ``test_registry.py``
**Region:** ``tests/dataset/pagination/strategies/test_registry``

Pagination strategy registry tests.
"""

from __future__ import annotations

from ds_protocol_http_py_lib.dataset.pagination import PaginationStrategy, get_strategy
from ds_protocol_http_py_lib.dataset.pagination.strategies.cursor import (
    CursorPaginationStrategy,
)
from ds_protocol_http_py_lib.dataset.pagination.strategies.offset import (
    OffsetPaginationStrategy,
)
from ds_protocol_http_py_lib.dataset.pagination.strategies.page_number import (
    PageNumberPaginationStrategy,
)


def test_registry_contains_builtin_strategies() -> None:
    """Built-in strategies are registered via import-side opt-in."""
    assert isinstance(get_strategy(PaginationStrategy.OFFSET), OffsetPaginationStrategy)
    assert isinstance(
        get_strategy(PaginationStrategy.PAGE_NUMBER),
        PageNumberPaginationStrategy,
    )
    assert isinstance(get_strategy(PaginationStrategy.CURSOR), CursorPaginationStrategy)
