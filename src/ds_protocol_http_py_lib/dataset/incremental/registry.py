"""
**File:** ``registry.py``
**Region:** ``ds_protocol_http_py_lib/dataset/incremental/registry``

Opt-in registry for incremental rulesets.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, TypeVar

if TYPE_CHECKING:
    from collections.abc import Callable

    from .enums import IncrementalStrategy
    from .rules import IncrementalRules

_RULES_REGISTRY: dict[IncrementalStrategy, IncrementalRules] = {}

T = TypeVar("T", bound=type)


def register(strategy: IncrementalStrategy) -> Callable[[T], T]:
    """
    Class decorator that registers an incremental ruleset.

    Adding a new ruleset is backward compatible: register a new enum member
    and handler module without changing Paginate.
    """

    def decorator(cls: T) -> T:
        if strategy in _RULES_REGISTRY:
            raise ValueError(f"Incremental strategy already registered: {strategy}")
        _RULES_REGISTRY[strategy] = cls()
        return cls

    return decorator


def get_rules(strategy: IncrementalStrategy) -> IncrementalRules:
    """
    Resolve a registered incremental ruleset.

    Raises:
        KeyError: If no ruleset is registered for ``strategy``.
    """
    try:
        return _RULES_REGISTRY[strategy]
    except KeyError as exc:
        raise KeyError(
            f"No incremental strategy registered for '{strategy}'. Import the strategy module or register a handler.",
        ) from exc
