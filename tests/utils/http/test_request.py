"""
**File:** ``test_request.py``
**Region:** ``tests/utils/http/test_request``

Unit tests for RequestSnapshot injection and header lookup.
"""

from __future__ import annotations

from typing import Any, cast

import pytest

from ds_protocol_http_py_lib.enums import HttpMethod
from ds_protocol_http_py_lib.utils.http.request import (
    InjectLocation,
    RequestSnapshot,
    get_header,
)


def _base_request() -> RequestSnapshot:
    return RequestSnapshot(
        url="https://api.example.com/items",
        method=HttpMethod.GET,
        params={},
        headers={},
        json={},
    )


def test_inject_header_and_body() -> None:
    """HEADER and BODY write into headers and JSON body on a clone."""
    request = _base_request()
    headered = request.inject("X-Cursor", "tok-1", InjectLocation.HEADER)
    assert headered.headers == {"X-Cursor": "tok-1"}
    assert request.headers == {}

    bodied = request.inject("filter", {"since": "2024-01-01"}, InjectLocation.BODY)
    assert bodied.json == {"filter": {"since": "2024-01-01"}}
    assert request.json == {}


def test_inject_when_containers_absent() -> None:
    """Injection initializes None containers on the clone."""
    bare = RequestSnapshot(url="https://api.example.com/items", method=HttpMethod.GET)
    assert bare.inject("X-A", "1", InjectLocation.HEADER).headers == {"X-A": "1"}
    assert bare.inject("offset", 0, InjectLocation.BODY).json == {"offset": 0}


def test_inject_unsupported_location_raises() -> None:
    """Unknown inject location raises ValueError."""
    with pytest.raises(ValueError, match="Unsupported inject location"):
        _base_request().inject("x", 1, cast("InjectLocation", cast("Any", "path")))


def test_get_header_case_insensitive() -> None:
    """Header lookup is case-insensitive; empty values are None."""
    headers = {"X-Next": "tok", "X-Empty": "", "X-None": None, "X-Num": 42}
    assert get_header(headers, "x-next") == "tok"
    assert get_header(headers, "x-empty") is None
    assert get_header(headers, "x-none") is None
    assert get_header(headers, "x-num") == "42"
    assert get_header(headers, "missing") is None
