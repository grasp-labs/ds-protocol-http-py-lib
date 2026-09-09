"""
**File:** ``settings.py``
**Region:** ``ds_protocol_http_py_lib/dataset/incremental/settings``

Incremental (shifting-scope) settings for HttpDataset reads.

Example:
    >>> IncrementalSettings(
    ...     param="updated_since",
    ...     location=InjectLocation.QUERY,
    ...     watermark_path="updated_at",
    ... )
"""

from dataclasses import dataclass

from ds_common_serde_py_lib import Serializable

from ...utils.http.request import InjectLocation
from .enums import IncrementalStrategy


@dataclass(kw_only=True)
class IncrementalSettings(Serializable):
    """
    Instruction nest for incremental rules used by Paginate.

    Instruction (stable): which request slot carries the lower bound and which
    response field advances the high-watermark.

    State (runtime): the watermark value itself lives in ``checkpoint``, owned
    by the caller. Paginate reads it on prepare and writes it on commit.
    """

    strategy: IncrementalStrategy = IncrementalStrategy.WATERMARK
    """Incremental ruleset. Declared explicitly; never inferred."""

    param: str
    """Name injected into the next run's request (query, header, or body key)."""

    location: InjectLocation = InjectLocation.QUERY
    """Where the watermark is injected on the request."""

    watermark_path: str
    """Dotted path on each output row used to compute the new high-watermark."""
