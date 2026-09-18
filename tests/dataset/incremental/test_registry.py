"""
**File:** ``test_registry.py``
**Region:** ``tests/dataset/incremental/test_registry``

Incremental ruleset registry tests.
"""

from __future__ import annotations

from typing import Any, cast

import pytest

from ds_protocol_http_py_lib.dataset.incremental import (
    IncrementalStrategy,
    WatermarkRules,
    get_rules,
    register,
)


def test_registry_contains_builtin_watermark_rules() -> None:
    """Built-in watermark ruleset is registered via import-side opt-in."""
    assert isinstance(get_rules(IncrementalStrategy.WATERMARK), WatermarkRules)


def test_register_rejects_duplicate_strategy() -> None:
    """Re-registering an already-registered strategy raises ValueError."""
    with pytest.raises(ValueError, match="already registered"):

        @register(IncrementalStrategy.WATERMARK)
        class _DuplicateWatermark:  # pragma: no cover - decorator raises before use
            pass


def test_get_rules_unknown_raises_key_error() -> None:
    """Resolving an unregistered strategy value raises KeyError."""
    with pytest.raises(KeyError, match="No incremental strategy registered"):
        get_rules(cast("IncrementalStrategy", cast("Any", "unknown")))
