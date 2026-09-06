"""
**File:** ``extract.py``
**Region:** ``ds_protocol_http_py_lib/dataset/pagination/extract``

Response value extraction helpers for pagination.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Mapping


def parse_json_body(content: bytes | str | None) -> Any:
    """
    Parse response content as JSON.

    Returns:
        Parsed JSON value, or ``None`` when the payload is empty.
    """
    if not content:
        return None
    if isinstance(content, bytes):
        content = content.decode("utf-8")
    return json.loads(content)


def extract_path(data: Any, path: str) -> Any:
    """
    Extract a value from nested JSON using a simple dotted path.

    - ``$`` returns ``data`` itself (root).
    - ``a.b.c`` walks dict keys; integer segments index lists.

    Returns:
        The value at ``path``, or ``None`` when a segment is missing.
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


def extract_items(body: Any, items_path: str) -> list[Any]:
    """
    Extract the record list at ``items_path``.

    Returns:
        The list of records, or an empty list when the path is missing.

    Raises:
        TypeError: If the path resolves to a non-list value.
    """
    value = extract_path(body, items_path)
    if value is None:
        return []
    if not isinstance(value, list):
        raise TypeError(
            f"items_path '{items_path}' did not resolve to a list (got {type(value).__name__})",
        )
    return value


def extract_header(headers: Mapping[str, Any], name: str) -> str | None:
    """
    Case-insensitive header lookup.

    Returns:
        Header value as ``str``, or ``None`` when absent or empty.
    """
    target = name.lower()
    for key, value in headers.items():
        if str(key).lower() == target:
            if value is None or value == "":
                return None
            return value if isinstance(value, str) else str(value)
    return None
