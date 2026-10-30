"""
**File:** ``test_request.py``
**Region:** ``tests/utils/http/test_request``

Unit tests for RequestSnapshot injection and header lookup.
"""

from __future__ import annotations

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


def test_inject_body_writes_data_when_data_is_set() -> None:
    """BODY follows the form body requests will send, and leaves json unchanged."""
    request = RequestSnapshot(
        url="https://api.example.com/items",
        method=HttpMethod.POST,
        data={"status": "open"},
        json={"ignored": True},
    )
    bodied = request.inject("cursor", "tok-1", InjectLocation.BODY)
    assert bodied.data == {"status": "open", "cursor": "tok-1"}
    assert bodied.json == {"ignored": True}
    assert request.data == {"status": "open"}


def test_inject_body_rejects_non_dict_data() -> None:
    """A raw data body cannot take an injected field."""
    request = RequestSnapshot(
        url="https://api.example.com/items",
        method=HttpMethod.POST,
        data="status=open",
    )
    with pytest.raises(ValueError, match="requires data to be a dict"):
        request.inject("cursor", "tok-1", InjectLocation.BODY)


def test_inject_when_containers_absent() -> None:
    """Injection initializes None containers on the clone."""
    bare = RequestSnapshot(url="https://api.example.com/items", method=HttpMethod.GET)
    assert bare.inject("X-A", "1", InjectLocation.HEADER).headers == {"X-A": "1"}
    assert bare.inject("offset", 0, InjectLocation.BODY).json == {"offset": 0}


def test_get_header_case_insensitive() -> None:
    """Header lookup is case-insensitive; empty values are None."""
    headers = {"X-Next": "tok", "X-Empty": "", "X-None": None, "X-Num": 42}
    assert get_header(headers, "x-next") == "tok"
    assert get_header(headers, "x-empty") is None
    assert get_header(headers, "x-none") is None
    assert get_header(headers, "x-num") == "42"
    assert get_header(headers, "missing") is None
