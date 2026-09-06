"""
**File:** ``test_apply.py``
**Region:** ``tests/dataset/incremental/test_apply``

Incremental (shifting-scope) single-request apply tests.
"""

from __future__ import annotations

import json
import uuid
from types import SimpleNamespace
from typing import Any

import pandas as pd
import pytest
from ds_resource_plugin_py_lib.common.resource.dataset.errors import ReadError
from ds_resource_plugin_py_lib.common.resource.errors import ResourceException
from ds_resource_plugin_py_lib.common.resource.linked_service.errors import (
    AuthenticationError,
)

from ds_protocol_http_py_lib.dataset.http import (
    HttpDataset,
    HttpDatasetSettings,
    HttpReadSettings,
)
from ds_protocol_http_py_lib.dataset.incremental import IncrementalSettings
from ds_protocol_http_py_lib.dataset.incremental.apply import apply
from tests.dataset.helpers import linked_service


def test_incremental_watermark_advances_only_on_success() -> None:
    """Incremental injects prior watermark and advances only after full success."""
    seen: list[Any] = []

    def fake_request(**kwargs: Any) -> SimpleNamespace:
        seen.append((kwargs.get("params") or {}).get("updated_since"))
        return SimpleNamespace(
            content=json.dumps(
                [
                    {"id": 1, "updated_at": "2024-01-02"},
                    {"id": 2, "updated_at": "2024-01-05"},
                ],
            ).encode("utf-8"),
            headers={},
        )

    dataset = HttpDataset(
        id=uuid.uuid4(),
        name="ds",
        version="1.0.0",
        linked_service=linked_service(fake_request),
        settings=HttpDatasetSettings(
            url="https://example.test/orders",
            read=HttpReadSettings(
                incremental=IncrementalSettings(
                    param="updated_since",
                    watermark_path="updated_at",
                ),
            ),
        ),
        checkpoint={"incremental": {"watermark": "2024-01-01"}},
    )
    dataset.read()
    assert seen == ["2024-01-01"]
    assert dataset.checkpoint["incremental"]["watermark"] == "2024-01-05"


def test_apply_requires_incremental_settings() -> None:
    """Calling apply without incremental settings raises ValueError."""
    dataset = HttpDataset(
        id=uuid.uuid4(),
        name="ds",
        version="1.0.0",
        linked_service=linked_service(lambda **_: SimpleNamespace(content=b"[]", headers={})),
        settings=HttpDatasetSettings(url="https://example.test/orders"),
    )
    with pytest.raises(ValueError, match=r"requires settings\.read\.incremental"):
        apply(dataset)


def test_apply_maps_resource_exception_to_read_error() -> None:
    """Generic ResourceException from the connection becomes ReadError."""

    def fake_request(**kwargs: Any) -> SimpleNamespace:
        raise ResourceException(message="upstream failed", status_code=502, details={})

    dataset = HttpDataset(
        id=uuid.uuid4(),
        name="ds",
        version="1.0.0",
        linked_service=linked_service(fake_request),
        settings=HttpDatasetSettings(
            url="https://example.test/orders",
            read=HttpReadSettings(
                incremental=IncrementalSettings(param="updated_since", watermark_path="updated_at"),
            ),
        ),
    )
    with pytest.raises(ReadError, match="upstream failed") as exc_info:
        dataset.read()
    assert exc_info.value.status_code == 502
    assert exc_info.value.details["type"] == dataset.type.value


def test_apply_rethrows_authentication_error() -> None:
    """AuthenticationError from the connection is re-raised unchanged."""

    def fake_request(**kwargs: Any) -> SimpleNamespace:
        raise AuthenticationError(message="denied", details={})

    dataset = HttpDataset(
        id=uuid.uuid4(),
        name="ds",
        version="1.0.0",
        linked_service=linked_service(fake_request),
        settings=HttpDatasetSettings(
            url="https://example.test/orders",
            read=HttpReadSettings(
                incremental=IncrementalSettings(param="updated_since", watermark_path="updated_at"),
            ),
        ),
    )
    with pytest.raises(AuthenticationError, match="denied"):
        dataset.read()


def test_apply_empty_content_yields_empty_dataframe() -> None:
    """Empty response content assigns an empty DataFrame and still commits."""

    def fake_request(**kwargs: Any) -> SimpleNamespace:
        return SimpleNamespace(content=b"", headers={})

    dataset = HttpDataset(
        id=uuid.uuid4(),
        name="ds",
        version="1.0.0",
        linked_service=linked_service(fake_request),
        settings=HttpDatasetSettings(
            url="https://example.test/orders",
            read=HttpReadSettings(
                incremental=IncrementalSettings(param="updated_since", watermark_path="updated_at"),
            ),
        ),
    )
    dataset.read()
    assert isinstance(dataset.output, pd.DataFrame)
    assert dataset.output.empty
