"""
**File:** ``__init__.py``
**Region:** ``ds_protocol_http_py_lib/utils``

Shared utilities used by linked services and datasets.

- ``json_utils`` — JSON parse / dotted-path / list helpers
- ``http`` — HTTP client, request snapshots, inject locations, rate limiting
"""

from . import http
from .json_utils import find_keys_in_json, get_list, get_path, parse_json

__all__ = [
    "find_keys_in_json",
    "get_list",
    "get_path",
    "http",
    "parse_json",
]
