"""
**File:** ``helpers.py``
**Region:** ``tests/dataset/helpers``

Shared helpers for HttpDataset tests.
"""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any, cast


def linked_service(handler: Any) -> Any:
    connection = SimpleNamespace(request=handler)
    return cast("Any", SimpleNamespace(connection=connection, close=lambda: None))


def json_response(
    payload: dict[str, Any] | list[Any],
    headers: dict[str, str] | None = None,
) -> SimpleNamespace:
    return SimpleNamespace(
        content=json.dumps(payload).encode("utf-8"),
        headers=headers or {},
    )
