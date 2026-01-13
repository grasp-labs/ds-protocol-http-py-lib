"""
**File:** ``json_utils.py``
**Region:** ``ds_protocol_http_py_lib/utils/json_utils``

Utility functions for working with JSON data structures.

Example:
    >>> data = {"user": {"token": "abc123"}}
    >>> find_keys_in_json(data, {"token"})
    'abc123'
"""

from typing import Any


def find_keys_in_json(json_data: dict[str, Any] | list[Any], target_keys: set[str]) -> str | None:
    """
    Recursively search for a set of keys in a nested JSON structure and return their value.

    Args:
        json_data: The JSON data to search through.
        target_keys: A set of keys to search for.

    Returns:
        The value of the found key as a string, or None if no key is found.

    Example:
        >>> data = {"user": {"token": "abc123"}}
        >>> find_keys_in_json(data, {"token"})
        'abc123'
    """
    if isinstance(json_data, dict):
        for key, value in json_data.items():
            if key in target_keys:
                if isinstance(value, str):
                    return value
                return str(value)
            elif isinstance(value, (dict, list)):
                result = find_keys_in_json(value, target_keys)
                if result is not None:
                    return result
    elif isinstance(json_data, list):
        for item in json_data:
            result = find_keys_in_json(item, target_keys)
            if result is not None:
                return result
    return None
