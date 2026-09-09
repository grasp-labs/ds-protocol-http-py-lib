"""
**File:** ``enums.py``
**Region:** ``ds_protocol_http_py_lib/dataset/incremental/enums``

Incremental ruleset enums.
"""

from enum import StrEnum


class IncrementalStrategy(StrEnum):
    """Declared incremental rulesets supported by Paginate."""

    WATERMARK = "watermark"
    """Param-injected high-watermark across runs."""
