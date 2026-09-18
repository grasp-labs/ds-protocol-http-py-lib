"""
**File:** ``test_registry.py``
**Region:** ``tests/dataset/pagination/strategies/test_registry``

Pagination strategy registry tests.
"""

from __future__ import annotations

from typing import Any, cast

import pytest

from ds_protocol_http_py_lib.dataset.pagination import (
    PaginationStrategy,
    get_strategy,
    register,
)
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


def test_register_rejects_duplicate_strategy() -> None:
    """Re-registering an already-registered strategy raises ValueError."""
    with pytest.raises(ValueError, match="already registered"):

        @register(PaginationStrategy.OFFSET)
        class _DuplicateOffset:  # pragma: no cover - decorator raises before use
            pass


def test_get_strategy_unknown_raises_key_error() -> None:
    """Resolving an unregistered strategy value raises KeyError."""
    with pytest.raises(KeyError, match="No pagination strategy registered"):
        get_strategy(cast("PaginationStrategy", cast("Any", "unknown")))
