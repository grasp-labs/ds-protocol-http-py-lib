"""
**File:** ``__init__.py``
**Region:** ``ds_protocol_http_py_lib/dataset/pagination``

HTTP dataset pagination: settings, enums, and strategy registry.
"""

# Opt-in registration of built-in strategies.
from . import strategies as _strategies  # noqa: F401
from .enums import ExtractSource, InjectLocation, PaginationStrategy
from .registry import get_strategy, register
from .settings import (
    CursorPaginationSettings,
    OffsetPaginationSettings,
    PageNumberPaginationSettings,
    PaginationSettings,
)

__all__ = [
    "CursorPaginationSettings",
    "ExtractSource",
    "InjectLocation",
    "OffsetPaginationSettings",
    "PageNumberPaginationSettings",
    "PaginationSettings",
    "PaginationStrategy",
    "get_strategy",
    "register",
]
