"""
**File:** ``registry.py``
**Region:** ``ds_protocol_http_py_lib/dataset/pagination/registry``

Opt-in registry for pagination strategy handlers.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, TypeVar

if TYPE_CHECKING:
    from collections.abc import Callable

    from .base import PaginationStrategyHandler
    from .enums import PaginationStrategy

_STRATEGY_REGISTRY: dict[PaginationStrategy, PaginationStrategyHandler] = {}

T = TypeVar("T", bound=type)


def register(strategy: PaginationStrategy) -> Callable[[T], T]:
    """
    Class decorator that registers a strategy handler.

    Adding a new strategy is backward compatible: register a new enum member
    and handler module without changing the paginate loop.
    """

    def decorator(cls: T) -> T:
        if strategy in _STRATEGY_REGISTRY:
            raise ValueError(f"Pagination strategy already registered: {strategy}")
        _STRATEGY_REGISTRY[strategy] = cls()
        return cls

    return decorator


def get_strategy(strategy: PaginationStrategy) -> PaginationStrategyHandler:
    """
    Resolve a registered strategy handler.

    Raises:
        KeyError: If no handler is registered for ``strategy``.
    """
    try:
        return _STRATEGY_REGISTRY[strategy]
    except KeyError as exc:
        raise KeyError(
            f"No pagination strategy registered for '{strategy}'. Import the strategy module or register a handler.",
        ) from exc
