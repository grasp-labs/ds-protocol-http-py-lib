"""
**File:** ``enums.py``
**Region:** ``ds_protocol_http_py_lib/dataset/pagination/enums``

Pagination strategy and extract-source enums.
"""

from enum import StrEnum


class PaginationStrategy(StrEnum):
    """Declared pagination mechanisms supported by HttpDataset."""

    OFFSET = "offset"
    """Offset / limit pagination."""

    PAGE_NUMBER = "page_number"
    """Page ordinal / page size pagination."""

    CURSOR = "cursor"
    """Opaque cursor / token pagination."""


class ExtractSource(StrEnum):
    """Where a pagination value is read from the response."""

    BODY = "body"
    """JSON response body path."""

    HEADER = "header"
    """Response header name."""
