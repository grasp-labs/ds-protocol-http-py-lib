"""
**File:** ``watermark.py``
**Region:** ``ds_protocol_http_py_lib/dataset/incremental/watermark``

Compatibility helpers over :class:`WatermarkRules`.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from .strategies.watermark import WatermarkRules

if TYPE_CHECKING:
    import pandas as pd

    from ...utils.http.request import RequestSnapshot
    from .settings import IncrementalSettings


def inject(
    request: RequestSnapshot,
    checkpoint: dict[str, Any],
    settings: IncrementalSettings,
) -> RequestSnapshot:
    """Apply watermark from checkpoint onto the request (or leave unchanged)."""
    return WatermarkRules().prepare(request, checkpoint, settings)


def commit(
    checkpoint: dict[str, Any],
    output: pd.DataFrame,
    settings: IncrementalSettings,
) -> None:
    """
    Clear pagination slice (legacy) and advance watermark via WatermarkRules.

    Raises:
        TypeError: If watermark values are not mutually comparable.
    """
    checkpoint.pop("pagination", None)
    WatermarkRules().commit(checkpoint, output, settings)
