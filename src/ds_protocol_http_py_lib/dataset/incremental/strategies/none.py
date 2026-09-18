"""
**File:** ``none.py``
**Region:** ``ds_protocol_http_py_lib/dataset/incremental/strategies/none``

No-op incremental rules (full load; checkpoint watermark untouched).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from ..rules import IncrementalRules

if TYPE_CHECKING:
    import pandas as pd

    from ....utils.http.request import RequestSnapshot
    from ..settings import IncrementalSettings


class NoIncrementalRules(IncrementalRules):
    """Skip prepare/commit when incremental settings are absent."""

    def prepare(
        self,
        request: RequestSnapshot,
        checkpoint: dict[str, Any],
        settings: IncrementalSettings | None,
    ) -> RequestSnapshot:
        del checkpoint, settings
        return request

    def commit(
        self,
        checkpoint: dict[str, Any],
        output: pd.DataFrame,
        settings: IncrementalSettings | None,
    ) -> None:
        del checkpoint, output, settings
