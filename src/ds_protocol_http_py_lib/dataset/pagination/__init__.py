"""
**File:** ``__init__.py``
**Region:** ``ds_protocol_http_py_lib/dataset/pagination``

HTTP dataset pagination: settings, enums, strategy registry, and Paginate composer.
"""

from .enums import ExtractSource, PaginationStrategy
from .paginate import Paginate
from .registry import get_strategy, register
from .settings import (
    CursorPaginationSettings,
    OffsetPaginationSettings,
    PageNumberPaginationSettings,
    PaginationSettings,
)
from .strategies import (
    CursorPaginationStrategy,
    OffsetPaginationStrategy,
    PageNumberPaginationStrategy,
    PaginationStrategyHandler,
)

__all__ = [
    "CursorPaginationSettings",
    "CursorPaginationStrategy",
    "ExtractSource",
    "OffsetPaginationSettings",
    "OffsetPaginationStrategy",
    "PageNumberPaginationSettings",
    "PageNumberPaginationStrategy",
    "Paginate",
    "PaginationSettings",
    "PaginationStrategy",
    "PaginationStrategyHandler",
    "get_strategy",
    "register",
]
