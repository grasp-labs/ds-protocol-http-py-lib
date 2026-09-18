"""
**File:** ``__init__.py``
**Region:** ``ds_protocol_http_py_lib/dataset``

HTTP Dataset

This module implements a dataset for HTTP APIs.
"""

from ..utils.http.request import InjectLocation
from .http import HttpDataset, HttpDatasetSettings, HttpReadSettings
from .incremental import IncrementalSettings, IncrementalStrategy
from .pagination import (
    CursorPaginationSettings,
    ExtractSource,
    OffsetPaginationSettings,
    PageNumberPaginationSettings,
    Paginate,
    PaginationSettings,
    PaginationStrategy,
)

__all__ = [
    "CursorPaginationSettings",
    "ExtractSource",
    "HttpDataset",
    "HttpDatasetSettings",
    "HttpReadSettings",
    "IncrementalSettings",
    "IncrementalStrategy",
    "InjectLocation",
    "OffsetPaginationSettings",
    "PageNumberPaginationSettings",
    "Paginate",
    "PaginationSettings",
    "PaginationStrategy",
]
