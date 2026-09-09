"""
**File:** ``test_json_utils.py``
**Region:** ``tests/utils/test_json_utils``

JSON utility tests.

Covers:
- Recursive token/key lookup across nested dict/list structures.
- Normalization of matched values to string.
- None result when target keys are not present.
"""

from __future__ import annotations

import pytest

from ds_protocol_http_py_lib.utils.json_utils import find_keys_in_json, get_list, get_path, parse_json


def test_find_keys_in_json_finds_string_value() -> None:
    """
    It returns the first matching token value as a string.
    """

    data = {"user": {"token": "abc123"}}
    assert find_keys_in_json(data, {"token"}) == "abc123"


def test_find_keys_in_json_converts_non_string_value_to_string() -> None:
    """
    It stringifies non-string values for matched keys.
    """

    data = {"token": 123}
    assert find_keys_in_json(data, {"token"}) == "123"


def test_find_keys_in_json_searches_nested_dicts_and_lists() -> None:
    """
    It traverses nested dict/list structures.
    """

    data = [{"x": 1}, {"auth": {"data": {"access_token": "t"}}}]
    assert find_keys_in_json(data, {"access_token"}) == "t"


def test_find_keys_in_json_returns_none_when_not_found() -> None:
    """
    It returns None when no target key exists in the structure.
    """

    data = {"a": {"b": [1, 2, 3]}}
    assert find_keys_in_json(data, {"missing"}) is None


def test_parse_json_empty_and_string_payload() -> None:
    """Empty payloads are None; bytes and str decode to objects."""
    assert parse_json(None) is None
    assert parse_json(b"") is None
    assert parse_json("") is None
    assert parse_json('{"a": 1}') == {"a": 1}
    assert parse_json(b'{"a": 1}') == {"a": 1}


def test_get_path_root_list_index_and_missing() -> None:
    """Dotted paths walk dicts/lists; missing segments yield None."""
    data = {"items": [{"id": 1}]}
    assert get_path(data, "$") is data
    assert get_path(data, "") is data
    assert get_path(data, "items.0.id") == 1
    assert get_path(data, "items.9") is None
    assert get_path(data, "items.not_an_int") is None
    assert get_path(data, "items.0.id.extra") is None
    assert get_path("scalar", "field") is None


def test_get_list_missing_and_non_list() -> None:
    """Missing list paths are empty; non-list values raise TypeError."""
    assert get_list({"data": None}, "data") == []
    assert get_list({}, "data") == []
    with pytest.raises(TypeError, match="did not resolve to a list"):
        get_list({"data": {"id": 1}}, "data")
