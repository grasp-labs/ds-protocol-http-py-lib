"""
**File:** ``watermark.py``
**Region:** ``ds_protocol_http_py_lib/dataset/incremental/watermark``

Incremental watermark checkpoint lifecycle (shifting scope across runs).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import pandas as pd

from ..pagination.extract import extract_path
from ..pagination.inject import RequestSnapshot, inject_value

if TYPE_CHECKING:
    from .settings import IncrementalSettings

_CHECKPOINT_KEY = "incremental"
_WATERMARK_KEY = "watermark"


def inject(
    request: RequestSnapshot,
    checkpoint: dict[str, Any],
    settings: IncrementalSettings,
) -> RequestSnapshot:
    """
    Apply the caller-provided watermark from ``checkpoint`` to the request.

    Reads ``checkpoint["incremental"]["watermark"]``. If absent, returns
    ``request`` unchanged (full load — no lower-bound param injected).
    """
    slice_ = checkpoint.get(_CHECKPOINT_KEY)
    if not isinstance(slice_, dict) or _WATERMARK_KEY not in slice_:
        return request

    watermark = slice_[_WATERMARK_KEY]
    if watermark is None:
        return request

    return inject_value(
        request,
        name=settings.param,
        value=watermark,
        location=settings.location,
    )


def commit(
    checkpoint: dict[str, Any],
    output: pd.DataFrame,
    settings: IncrementalSettings,
) -> None:
    """
    Finalize checkpoint after a successful read.

    Clears pagination traversal state and advances the incremental watermark
    to the max value found at ``settings.watermark_path`` across output rows.

    Raises:
        TypeError: If watermark values are not mutually comparable.
    """
    checkpoint.pop("pagination", None)
    if output.empty:
        return

    values = [
        value
        for record in output.to_dict(orient="records")
        if (value := extract_path(record, settings.watermark_path)) is not None
    ]
    if not values:
        return

    try:
        watermark: Any = max(values)
    except TypeError as exc:
        types = sorted({type(value).__name__ for value in values})
        raise TypeError(
            f"Cannot compute watermark at '{settings.watermark_path}': values are not comparable across types {types}",
        ) from exc

    if isinstance(watermark, pd.Timestamp):
        watermark = (
            watermark.date().isoformat()
            if watermark.hour == watermark.minute == watermark.second == 0 and watermark.nanosecond == 0
            else watermark.isoformat()
        )

    checkpoint[_CHECKPOINT_KEY] = {_WATERMARK_KEY: watermark}
