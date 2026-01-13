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

from ds_protocol_http_py_lib.utils.json_utils import find_keys_in_json


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
