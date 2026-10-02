"""
**File:** ``base.py``
**Region:** ``ds_protocol_http_py_lib/dataset/pagination/strategies/base``

Base ABC for registered pagination strategies (page-variation hooks only).

Concrete strategies (offset, page-number, cursor, …) inherit this. The HTTP
drain loop lives on :class:`~dataset.pagination.paginate.Paginate`, which
*uses* a strategy — strategies do not own ``run``.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Generic, TypeVar

if TYPE_CHECKING:
    from ....utils.http.request import RequestSnapshot

ConfigT = TypeVar("ConfigT")


@dataclass
class PageState:
    """Strategy-owned traversal state for one paginated read."""

    values: dict[str, Any] = field(default_factory=dict)
    """Opaque strategy values (offset, page, cursor, …)."""

    page_index: int = 0
    """Zero-based count of pages fetched so far."""


class PaginationStrategyHandler(abc.ABC, Generic[ConfigT]):
    """
    Page-variation contract parameterized by the strategy settings nest.

    Each concrete strategy binds ``ConfigT`` to its nest type (e.g.
    ``CursorPaginationSettings``) so hook signatures stay precise.
    """

    @abc.abstractmethod
    def initial_state(
        self,
        cfg: ConfigT,
        checkpoint_slice: dict[str, Any] | None,
    ) -> PageState:
        """Build the starting page state, optionally restoring from checkpoint."""

    @abc.abstractmethod
    def inject(
        self,
        request: RequestSnapshot,
        state: PageState,
        cfg: ConfigT,
    ) -> RequestSnapshot:
        """Return a request snapshot with pagination values applied."""

    @abc.abstractmethod
    def advance(
        self,
        *,
        body: Any,
        headers: Any,
        items: list[Any],
        state: PageState,
        cfg: ConfigT,
    ) -> PageState:
        """Advance state after a successful page response."""

    @abc.abstractmethod
    def should_stop(
        self,
        *,
        body: Any,
        headers: Any,
        items: list[Any],
        state: PageState,
        cfg: ConfigT,
    ) -> bool:
        """Return True when traversal should terminate after this page."""

    @abc.abstractmethod
    def to_checkpoint(self, state: PageState) -> dict[str, Any]:
        """Serialize traversal state into the checkpoint ``pagination`` slice."""

    @abc.abstractmethod
    def from_checkpoint(self, data: dict[str, Any]) -> PageState:
        """Restore traversal state from a checkpoint ``pagination`` slice."""


def is_short_or_empty_page(items: list[Any], page_size: int) -> bool:
    """True when the page is empty or shorter than the requested page size."""
    return len(items) < page_size
