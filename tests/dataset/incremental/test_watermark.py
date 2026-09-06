"""
**File:** ``test_watermark.py``
**Region:** ``tests/dataset/incremental/test_watermark``

Unit tests for incremental watermark inject and commit helpers.
"""

from __future__ import annotations

import pandas as pd
import pytest

from ds_protocol_http_py_lib.dataset.incremental import IncrementalSettings
from ds_protocol_http_py_lib.dataset.incremental.watermark import commit, inject
from ds_protocol_http_py_lib.dataset.pagination.inject import RequestSnapshot
from ds_protocol_http_py_lib.enums import HttpMethod


def _request() -> RequestSnapshot:
    """Build a blank GET snapshot for watermark injection.

    Returns:
        Request snapshot with empty query params.
    """
    return RequestSnapshot(
        url="https://example.test/orders",
        method=HttpMethod.GET,
        params={},
    )


def test_inject_returns_unchanged_when_watermark_absent() -> None:
    """No checkpoint watermark and no initial seed leaves the request untouched."""
    settings = IncrementalSettings(param="updated_since", watermark_path="updated_at")
    request = _request()
    assert inject(request, {}, settings) is request


def test_commit_skips_empty_output_and_missing_path() -> None:
    """Empty frames and rows without the watermark path do not advance state."""
    settings = IncrementalSettings(param="updated_since", watermark_path="updated_at")
    checkpoint: dict = {"pagination": {"offset": 2}}
    commit(checkpoint, pd.DataFrame(), settings)
    assert "pagination" not in checkpoint
    assert "incremental" not in checkpoint

    checkpoint = {"pagination": {"offset": 1}}
    commit(checkpoint, pd.DataFrame([{"id": 1}]), settings)
    assert "pagination" not in checkpoint
    assert "incremental" not in checkpoint


def test_commit_raises_on_incomparable_watermark_types() -> None:
    """Mixed incomparable types at the watermark path raise TypeError."""
    settings = IncrementalSettings(param="updated_since", watermark_path="updated_at")
    output = pd.DataFrame(
        [
            {"updated_at": "2024-01-01"},
            {"updated_at": 10},
        ],
    )
    with pytest.raises(TypeError, match="not comparable"):
        commit({}, output, settings)


def test_commit_formats_timestamp_date_and_datetime() -> None:
    """Timestamp watermarks use date ISO when midnight, else full ISO."""
    settings = IncrementalSettings(param="updated_since", watermark_path="updated_at")

    midnight = pd.DataFrame([{"updated_at": pd.Timestamp("2024-03-01")}])
    checkpoint: dict = {}
    commit(checkpoint, midnight, settings)
    assert checkpoint["incremental"]["watermark"] == "2024-03-01"

    daytime = pd.DataFrame([{"updated_at": pd.Timestamp("2024-03-01 15:30:00")}])
    checkpoint = {}
    commit(checkpoint, daytime, settings)
    assert checkpoint["incremental"]["watermark"] == "2024-03-01T15:30:00"


def test_commit_stores_non_timestamp_watermark_as_is() -> None:
    """Non-Timestamp max values are written to the checkpoint unchanged."""
    settings = IncrementalSettings(param="updated_since", watermark_path="updated_at")
    checkpoint: dict = {}
    commit(
        checkpoint,
        pd.DataFrame([{"updated_at": "2024-04-01"}, {"updated_at": "2024-04-09"}]),
        settings,
    )
    assert checkpoint["incremental"]["watermark"] == "2024-04-09"
