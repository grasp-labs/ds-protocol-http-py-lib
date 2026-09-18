"""
**File:** ``rules.py``
**Region:** ``ds_protocol_http_py_lib/dataset/incremental/rules``

Incremental rulesets consulted by :class:`~dataset.pagination.paginate.Paginate`.

Rules prepare a request from ``checkpoint`` and commit after a successful drain.
They never issue HTTP.
"""

from __future__ import annotations

import abc
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    import pandas as pd

    from ...utils.http.request import RequestSnapshot
    from .settings import IncrementalSettings


class IncrementalRules(abc.ABC):
    """
    Shifting-scope rules for a paginated read.

    Instruction lives in ``IncrementalSettings``; state lives in ``checkpoint``.
    """

    @abc.abstractmethod
    def prepare(
        self,
        request: RequestSnapshot,
        checkpoint: dict[str, Any],
        settings: IncrementalSettings | None,
    ) -> RequestSnapshot:
        """Apply persisted resume state to the outbound request snapshot."""

    @abc.abstractmethod
    def commit(
        self,
        checkpoint: dict[str, Any],
        output: pd.DataFrame,
        settings: IncrementalSettings | None,
    ) -> None:
        """Advance persisted resume state after a fully successful drain.

        Does not clear ``checkpoint["pagination"]`` — that is owned by Paginate.
        """
