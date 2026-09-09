"""
**File:** ``test_settings.py``
**Region:** ``tests/dataset/pagination/test_settings``

PaginationSettings validation tests.
"""

from __future__ import annotations

import pytest
from ds_common_serde_py_lib.errors import DeserializationError

from ds_protocol_http_py_lib.dataset.pagination import (
    OffsetPaginationSettings,
    PaginationSettings,
    PaginationStrategy,
)


def test_missing_strategy_nest_raises() -> None:
    """Missing strategy nest fails at settings construction."""
    with pytest.raises(ValueError, match="offset is required"):
        PaginationSettings(strategy=PaginationStrategy.OFFSET)


def test_missing_strategy_nest_raises_on_deserialize() -> None:
    """Serializable.deserialize wraps the missing-nest ValueError."""
    with pytest.raises(DeserializationError) as exc_info:
        PaginationSettings.deserialize(
            {
                "strategy": "offset",
                "items_path": "data",
            },
        )
    assert "offset is required" in str(exc_info.value)


def test_deserialize_offset_settings() -> None:
    """Valid offset payload deserializes into PaginationSettings."""
    settings = PaginationSettings.deserialize(
        {
            "strategy": "offset",
            "items_path": "data",
            "offset": {"page_size": 50, "total_path": "page.total"},
        },
    )
    assert settings.strategy is PaginationStrategy.OFFSET
    assert isinstance(settings.strategy_config, OffsetPaginationSettings)
    assert settings.strategy_config.page_size == 50
