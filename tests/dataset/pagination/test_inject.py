"""
**File:** ``test_inject.py``
**Region:** ``tests/dataset/pagination/test_inject``

Unit tests for request snapshot value injection.
"""

from __future__ import annotations

from typing import Any, cast

import pytest

from ds_protocol_http_py_lib.dataset.pagination import InjectLocation
from ds_protocol_http_py_lib.dataset.pagination.inject import (
    RequestSnapshot,
    inject_value,
)
from ds_protocol_http_py_lib.enums import HttpMethod


def _base_request() -> RequestSnapshot:
    """Build a minimal request snapshot for injection tests.

    Returns:
        A GET snapshot with empty mutable containers.
    """
    return RequestSnapshot(
        url="https://api.example.com/items",
        method=HttpMethod.GET,
        params={},
        headers={},
        json={},
    )


def test_inject_value_header_and_body() -> None:
    """HEADER and BODY locations write into headers and JSON body respectively."""
    request = _base_request()
    headered = inject_value(
        request,
        name="X-Cursor",
        value="tok-1",
        location=InjectLocation.HEADER,
    )
    assert headered.headers == {"X-Cursor": "tok-1"}
    assert request.headers == {}

    bodied = inject_value(
        request,
        name="filter",
        value={"since": "2024-01-01"},
        location=InjectLocation.BODY,
    )
    assert bodied.json == {"filter": {"since": "2024-01-01"}}
    assert request.json == {}


def test_inject_value_header_body_when_containers_absent() -> None:
    """HEADER/BODY injection initializes None containers on the clone."""
    bare = RequestSnapshot(url="https://api.example.com/items", method=HttpMethod.GET)
    headered = inject_value(bare, name="X-A", value="1", location=InjectLocation.HEADER)
    assert headered.headers == {"X-A": "1"}
    bodied = inject_value(bare, name="offset", value=0, location=InjectLocation.BODY)
    assert bodied.json == {"offset": 0}


def test_inject_value_unsupported_location_raises() -> None:
    """An unknown inject location raises ValueError."""
    with pytest.raises(ValueError, match="Unsupported inject location"):
        inject_value(
            _base_request(),
            name="x",
            value=1,
            location=cast("InjectLocation", cast("Any", "path")),
        )
