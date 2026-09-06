"""
**File:** ``__init__.py``
**Region:** ``ds_protocol_http_py_lib/dataset``

HTTP Dataset

This module implements a dataset for HTTP APIs.
"""

from .http import HttpDataset, HttpDatasetSettings, HttpReadSettings
from .incremental import IncrementalSettings
from .pagination import (
    CursorPaginationSettings,
    ExtractSource,
    InjectLocation,
    OffsetPaginationSettings,
    PageNumberPaginationSettings,
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
    "InjectLocation",
    "OffsetPaginationSettings",
    "PageNumberPaginationSettings",
    "PaginationSettings",
    "PaginationStrategy",
]
