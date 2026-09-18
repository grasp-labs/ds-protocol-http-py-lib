"""
**File:** ``watermark.py``
**Region:** ``ds_protocol_http_py_lib/dataset/incremental/strategies/watermark``

High-watermark incremental ruleset.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import pandas as pd

from ....utils.json_utils import get_path
from ..enums import IncrementalStrategy
from ..registry import register
from ..rules import IncrementalRules

if TYPE_CHECKING:
    from ....utils.http.request import RequestSnapshot
    from ..settings import IncrementalSettings

_CHECKPOINT_KEY = "incremental"
_WATERMARK_KEY = "watermark"


@register(IncrementalStrategy.WATERMARK)
class WatermarkRules(IncrementalRules):
    """
    Resume on a caller-persisted high-watermark.

    Reads ``checkpoint["incremental"]["watermark"]`` on prepare. On commit,
    advances it to the max value at ``settings.watermark_path`` across rows.
    Does not clear pagination state — Paginate owns that.
    """

    def prepare(
        self,
        request: RequestSnapshot,
        checkpoint: dict[str, Any],
        settings: IncrementalSettings | None,
    ) -> RequestSnapshot:
        if settings is None:
            return request

        slice_ = checkpoint.get(_CHECKPOINT_KEY)
        if not isinstance(slice_, dict) or _WATERMARK_KEY not in slice_:
            return request

        watermark = slice_[_WATERMARK_KEY]
        if watermark is None:
            return request

        return request.inject(settings.param, watermark, settings.location)

    def commit(
        self,
        checkpoint: dict[str, Any],
        output: pd.DataFrame,
        settings: IncrementalSettings | None,
    ) -> None:
        if settings is None or output.empty:
            return

        values = [
            value
            for record in output.to_dict(orient="records")
            if (value := get_path(record, settings.watermark_path)) is not None
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
            watermark = watermark.isoformat()

        checkpoint[_CHECKPOINT_KEY] = {_WATERMARK_KEY: watermark}
