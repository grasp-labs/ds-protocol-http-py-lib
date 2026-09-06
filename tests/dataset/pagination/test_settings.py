"""
**File:** ``test_settings.py``
**Region:** ``tests/dataset/pagination/test_settings``

PaginationSettings validation tests.
"""

from __future__ import annotations

import pytest

from ds_protocol_http_py_lib.dataset.pagination import PaginationSettings, PaginationStrategy


def test_missing_strategy_nest_raises() -> None:
    """Missing strategy nest fails at settings construction."""
    with pytest.raises(ValueError, match="offset is required"):
        PaginationSettings(strategy=PaginationStrategy.OFFSET)
