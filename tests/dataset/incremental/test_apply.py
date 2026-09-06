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

from ds_protocol_http_py_lib.dataset.http import (
    HttpDataset,
    HttpDatasetSettings,
    HttpReadSettings,
)
from ds_protocol_http_py_lib.dataset.incremental import IncrementalSettings
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
