"""
**File:** ``test_paginate.py``
**Region:** ``tests/dataset/pagination/test_paginate``

HttpDataset pagination loop and checkpoint lifecycle integration tests.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from ds_resource_plugin_py_lib.common.resource.dataset.errors import ReadError
from ds_resource_plugin_py_lib.common.resource.errors import ResourceException

from ds_protocol_http_py_lib.dataset.http import (
    HttpDataset,
    HttpDatasetSettings,
    HttpReadSettings,
)
from ds_protocol_http_py_lib.dataset.incremental import IncrementalSettings
from ds_protocol_http_py_lib.dataset.pagination import (
    CursorPaginationSettings,
    OffsetPaginationSettings,
    PageNumberPaginationSettings,
    PaginationSettings,
    PaginationStrategy,
)
from ds_protocol_http_py_lib.dataset.pagination.paginate import paginate
from ds_protocol_http_py_lib.enums import HttpMethod
from tests.dataset.helpers import json_response, linked_service


def test_offset_pagination_concatenates_and_clears_checkpoint() -> None:
    """Offset pagination concatenates pages and clears pagination on success."""
    calls: list[dict[str, Any]] = []

    def fake_request(**kwargs: Any) -> Any:
        calls.append(kwargs)
        offset = int(kwargs["params"]["offset"])
        if offset == 0:
            return json_response({"data": [{"id": 1}, {"id": 2}], "meta": {"total": 3}})
        return json_response({"data": [{"id": 3}], "meta": {"total": 3}})

    dataset = HttpDataset(
        id=uuid.uuid4(),
        name="ds",
        version="1.0.0",
        linked_service=linked_service(fake_request),
        settings=HttpDatasetSettings(
            url="https://example.test/orders",
            method=HttpMethod.GET,
            read=HttpReadSettings(
                pagination=PaginationSettings(
                    strategy=PaginationStrategy.OFFSET,
                    items_path="data",
                    offset=OffsetPaginationSettings(page_size=2, total_path="meta.total"),
                ),
            ),
        ),
    )
    assert dataset.supports_checkpoint is True
    dataset.read()

    assert list(dataset.output["id"]) == [1, 2, 3]
    assert "pagination" not in dataset.checkpoint
    assert [c["params"]["offset"] for c in calls] == [0, 2]


def test_offset_failure_persists_pagination_resume_state() -> None:
    """Mid-run failure keeps next-page pagination state and leaves watermark untouched."""
    calls = {"n": 0}

    def fake_request(**kwargs: Any) -> Any:
        calls["n"] += 1
        if calls["n"] == 1:
            return json_response({"data": [{"id": 1}, {"id": 2}], "meta": {"total": 4}})
        raise ResourceException(message="boom", status_code=500, details={})

    dataset = HttpDataset(
        id=uuid.uuid4(),
        name="ds",
        version="1.0.0",
        linked_service=linked_service(fake_request),
        settings=HttpDatasetSettings(
            url="https://example.test/orders",
            read=HttpReadSettings(
                pagination=PaginationSettings(
                    strategy=PaginationStrategy.OFFSET,
                    items_path="data",
                    offset=OffsetPaginationSettings(page_size=2, total_path="meta.total"),
                ),
                incremental=IncrementalSettings(param="updated_since", watermark_path="id"),
            ),
        ),
        checkpoint={"incremental": {"watermark": 10}},
    )

    with pytest.raises(ReadError, match="boom"):
        dataset.read()

    assert dataset.checkpoint["incremental"] == {"watermark": 10}
    assert dataset.checkpoint["pagination"]["offset"] == 2
    assert list(dataset.output["id"]) == [1, 2]


def test_offset_resume_from_checkpoint() -> None:
    """Resume continues from checkpoint pagination offset without re-fetching earlier pages."""
    calls: list[int] = []

    def fake_request(**kwargs: Any) -> Any:
        offset = int(kwargs["params"]["offset"])
        calls.append(offset)
        return json_response({"data": [{"id": 3}], "meta": {"total": 3}})

    dataset = HttpDataset(
        id=uuid.uuid4(),
        name="ds",
        version="1.0.0",
        linked_service=linked_service(fake_request),
        settings=HttpDatasetSettings(
            url="https://example.test/orders",
            read=HttpReadSettings(
                pagination=PaginationSettings(
                    strategy=PaginationStrategy.OFFSET,
                    items_path="data",
                    offset=OffsetPaginationSettings(page_size=2, total_path="meta.total"),
                ),
            ),
        ),
        checkpoint={
            "pagination": {
                "strategy": "offset",
                "offset": 2,
                "limit": 2,
                "page_index": 1,
            },
        },
    )
    dataset.read()
    assert calls == [2]
    assert list(dataset.output["id"]) == [3]
    assert "pagination" not in dataset.checkpoint


def test_page_number_pagination() -> None:
    """Page-number strategy walks pages until short page."""

    def fake_request(**kwargs: Any) -> Any:
        page = int(kwargs["params"]["page"])
        if page == 1:
            return json_response({"results": [{"id": "a"}, {"id": "b"}]})
        return json_response({"results": [{"id": "c"}]})

    dataset = HttpDataset(
        id=uuid.uuid4(),
        name="ds",
        version="1.0.0",
        linked_service=linked_service(fake_request),
        settings=HttpDatasetSettings(
            url="https://example.test/customers",
            read=HttpReadSettings(
                pagination=PaginationSettings(
                    strategy=PaginationStrategy.PAGE_NUMBER,
                    items_path="results",
                    page_number=PageNumberPaginationSettings(
                        page_param="page",
                        page_size_param="per_page",
                        page_size=2,
                        start_page=1,
                    ),
                ),
            ),
        ),
    )
    dataset.read()
    assert list(dataset.output["id"]) == ["a", "b", "c"]


def test_cursor_pagination() -> None:
    """Cursor strategy echoes opaque tokens until the next cursor is empty."""

    def fake_request(**kwargs: Any) -> Any:
        cursor = (kwargs.get("params") or {}).get("cursor")
        if cursor is None:
            return json_response(
                {
                    "items": [{"id": "evt_01"}, {"id": "evt_02"}],
                    "response_metadata": {"next_cursor": "abc"},
                },
            )
        return json_response(
            {
                "items": [{"id": "evt_03"}],
                "response_metadata": {"next_cursor": ""},
            },
        )

    dataset = HttpDataset(
        id=uuid.uuid4(),
        name="ds",
        version="1.0.0",
        linked_service=linked_service(fake_request),
        settings=HttpDatasetSettings(
            url="https://example.test/events",
            read=HttpReadSettings(
                pagination=PaginationSettings(
                    strategy=PaginationStrategy.CURSOR,
                    items_path="items",
                    cursor=CursorPaginationSettings(
                        cursor_path="response_metadata.next_cursor",
                        cursor_param="cursor",
                        page_size_param="limit",
                        page_size=2,
                    ),
                ),
            ),
        ),
    )
    dataset.read()
    assert list(dataset.output["id"]) == ["evt_01", "evt_02", "evt_03"]
    assert "pagination" not in dataset.checkpoint


def test_incremental_with_pagination_resets_page_on_success() -> None:
    """Traversing scope resets on success; shifting scope (watermark) advances."""

    def fake_request(**kwargs: Any) -> Any:
        offset = int(kwargs["params"]["offset"])
        if offset == 0:
            return json_response(
                {
                    "data": [
                        {"id": 1, "updated_at": "2024-02-01"},
                        {"id": 2, "updated_at": "2024-02-02"},
                    ],
                },
            )
        return json_response({"data": [{"id": 3, "updated_at": "2024-02-03"}]})

    dataset = HttpDataset(
        id=uuid.uuid4(),
        name="ds",
        version="1.0.0",
        linked_service=linked_service(fake_request),
        settings=HttpDatasetSettings(
            url="https://example.test/orders",
            params={},
            read=HttpReadSettings(
                pagination=PaginationSettings(
                    strategy=PaginationStrategy.OFFSET,
                    items_path="data",
                    offset=OffsetPaginationSettings(page_size=2),
                ),
                incremental=IncrementalSettings(param="updated_since", watermark_path="updated_at"),
            ),
        ),
        checkpoint={
            "incremental": {"watermark": "2024-01-01"},
            "pagination": {
                "strategy": "offset",
                "offset": 0,
                "limit": 2,
                "page_index": 0,
            },
        },
    )
    dataset.read()
    assert "pagination" not in dataset.checkpoint
    assert dataset.checkpoint["incremental"]["watermark"] == "2024-02-03"
    assert len(dataset.output) == 3


def test_max_pages_raises() -> None:
    """Client max_pages ceiling raises when the API never terminates."""

    def fake_request(**kwargs: Any) -> Any:
        return json_response({"data": [{"id": 1}, {"id": 2}]})

    dataset = HttpDataset(
        id=uuid.uuid4(),
        name="ds",
        version="1.0.0",
        linked_service=linked_service(fake_request),
        settings=HttpDatasetSettings(
            url="https://example.test/orders",
            read=HttpReadSettings(
                pagination=PaginationSettings(
                    strategy=PaginationStrategy.OFFSET,
                    max_pages=2,
                    items_path="data",
                    offset=OffsetPaginationSettings(page_size=2),
                ),
            ),
        ),
    )
    with pytest.raises(ReadError, match="max_pages"):
        dataset.read()
    assert dataset.checkpoint["pagination"]["offset"] == 4


def test_checkpoint_strategy_mismatch_raises() -> None:
    """Resume rejects a checkpoint whose strategy does not match settings."""

    def fake_request(**kwargs: Any) -> Any:
        raise AssertionError("request should not be issued")

    dataset = HttpDataset(
        id=uuid.uuid4(),
        name="ds",
        version="1.0.0",
        linked_service=linked_service(fake_request),
        settings=HttpDatasetSettings(
            url="https://example.test/orders",
            read=HttpReadSettings(
                pagination=PaginationSettings(
                    strategy=PaginationStrategy.OFFSET,
                    items_path="data",
                    offset=OffsetPaginationSettings(page_size=2),
                ),
            ),
        ),
        checkpoint={
            "pagination": {
                "strategy": "cursor",
                "cursor": "tok",
                "page_size": 2,
                "page_index": 1,
            },
        },
    )
    with pytest.raises(ReadError, match="does not match"):
        dataset.read()


def test_paginate_requires_pagination_settings() -> None:
    """Calling paginate without pagination settings raises ValueError."""
    dataset = HttpDataset(
        id=uuid.uuid4(),
        name="ds",
        version="1.0.0",
        linked_service=linked_service(lambda **_: json_response({"data": []})),
        settings=HttpDatasetSettings(url="https://example.test/orders"),
    )
    with pytest.raises(ValueError, match=r"requires settings\.read\.pagination"):
        paginate(dataset)
