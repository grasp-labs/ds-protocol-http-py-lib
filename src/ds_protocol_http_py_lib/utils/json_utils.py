"""
**File:** ``json_utils.py``
**Region:** ``ds_protocol_http_py_lib/utils/json_utils``

Utility functions for working with JSON data structures.

Example:
    >>> data = {"user": {"token": "abc123"}}
    >>> find_keys_in_json(data, {"token"})
    'abc123'
    >>> get_path(data, "user.token")
    'abc123'
"""

from __future__ import annotations

import json
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


def parse_json(content: bytes | str | None) -> Any:
    """Parse JSON bytes/str; empty content returns ``None``."""
    if not content:
        return None
    if isinstance(content, bytes):
        content = content.decode("utf-8")
    return json.loads(content)


def get_path(data: Any, path: str) -> Any:
    """
    Read a value via dotted path (``a.b.0.c``).

    ``$`` / ``""`` returns ``data`` itself. Missing segments return ``None``.
    """
    if path in ("$", ""):
        return data

    current = data
    for segment in path.split("."):
        if isinstance(current, dict):
            current = current.get(segment)
            continue
        if isinstance(current, list):
            try:
                current = current[int(segment)]
            except (ValueError, IndexError):
                return None
            continue
        return None
    return current


def get_list(data: Any, path: str) -> list[Any]:
    """
    Read a list at ``path``; missing path yields ``[]``.

    Raises:
        TypeError: If the path resolves to a non-list value.
    """
    value = get_path(data, path)
    if value is None:
        return []
    if not isinstance(value, list):
        raise TypeError(
            f"path '{path}' did not resolve to a list (got {type(value).__name__})",
        )
    return value
