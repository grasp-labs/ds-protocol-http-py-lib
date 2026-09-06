"""
**File:** ``test_extract.py``
**Region:** ``tests/dataset/pagination/test_extract``

Unit tests for pagination response extraction helpers.
"""

from __future__ import annotations

import pytest

from ds_protocol_http_py_lib.dataset.pagination.extract import (
    extract_header,
    extract_items,
    extract_path,
    parse_json_body,
)


def test_parse_json_body_empty_and_string_payload() -> None:
    """Empty payloads yield None; string JSON is parsed without decoding."""
    assert parse_json_body(None) is None
    assert parse_json_body(b"") is None
    assert parse_json_body("") is None
    assert parse_json_body('{"a": 1}') == {"a": 1}
    assert parse_json_body(b'{"a": 1}') == {"a": 1}


def test_extract_path_root_list_index_and_missing() -> None:
    """Root paths, list indexing, and missing/invalid segments return correctly."""
    data = {"items": [{"id": 1}, {"id": 2}], "meta": {"total": 2}}
    assert extract_path(data, "$") is data
    assert extract_path(data, "") is data
    assert extract_path(data, "items.0.id") == 1
    assert extract_path(data, "items.9") is None
    assert extract_path(data, "items.not_an_int") is None
    assert extract_path(data, "items.0.id.extra") is None
    assert extract_path("scalar", "field") is None


def test_extract_items_missing_and_non_list() -> None:
    """Missing items_path yields []; a non-list value raises TypeError."""
    assert extract_items({"data": None}, "data") == []
    assert extract_items({}, "data") == []
    with pytest.raises(TypeError, match="did not resolve to a list"):
        extract_items({"data": {"id": 1}}, "data")


def test_extract_header_case_insensitive_empty_and_coercion() -> None:
    """Header lookup is case-insensitive; empty/None become None; non-str is coerced."""
    headers = {
        "X-Other": "skip",
        "X-Next": "tok",
        "X-Empty": "",
        "X-None": None,
        "X-Num": 42,
    }
    assert extract_header(headers, "x-next") == "tok"
    assert extract_header(headers, "x-empty") is None
    assert extract_header(headers, "x-none") is None
    assert extract_header(headers, "x-num") == "42"
    assert extract_header(headers, "missing") is None
