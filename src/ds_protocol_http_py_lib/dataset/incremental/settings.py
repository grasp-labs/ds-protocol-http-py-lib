"""
**File:** ``settings.py``
**Region:** ``ds_protocol_http_py_lib/dataset/incremental/settings``

Incremental (shifting-scope) settings for HttpDataset reads.

Example:
    >>> IncrementalSettings(
    ...     param="updated_since",
    ...     location=InjectLocation.QUERY,
    ...     watermark_path="updated_at",
    ...     initial_watermark="2024-01-01",
    ... )
"""

from dataclasses import dataclass
from typing import Any

from ds_common_serde_py_lib import Serializable

from ..pagination.enums import InjectLocation


@dataclass(kw_only=True)
class IncrementalSettings(Serializable):
    """
    Param-injected watermark strategy.

    Instruction (stable): which request slot carries the lower bound and which
    response field advances the high-watermark.

    State (runtime): the watermark value itself lives in ``checkpoint``.
    """

    param: str
    """Name injected into the next run's request (query, header, or body key)."""

    location: InjectLocation = InjectLocation.QUERY
    """Where the watermark is injected on the request."""

    watermark_path: str
    """Dotted path on each output row used to compute the new high-watermark."""

    initial_watermark: Any | None = None
    """Optional seed used when the checkpoint has no prior watermark."""
