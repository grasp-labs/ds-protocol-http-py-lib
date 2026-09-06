"""
**File:** ``base.py``
**Region:** ``ds_protocol_http_py_lib/dataset/pagination/base``

Pagination strategy protocol and shared helpers.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Protocol

if TYPE_CHECKING:
    from .inject import PageState, RequestSnapshot
    from .settings import StrategyConfig


class PaginationStrategyHandler(Protocol):
    """Runtime contract implemented by registered pagination strategies."""

    def initial_state(
        self,
        cfg: StrategyConfig,
        checkpoint_slice: dict[str, Any] | None,
    ) -> PageState:
        """Build the starting page state, optionally restoring from checkpoint."""
        ...

    def inject(
        self,
        request: RequestSnapshot,
        state: PageState,
        cfg: StrategyConfig,
    ) -> RequestSnapshot:
        """Return a request snapshot with pagination values applied."""
        ...

    def advance(
        self,
        *,
        body: Any,
        headers: Any,
        items: list[Any],
        state: PageState,
        cfg: StrategyConfig,
    ) -> PageState:
        """Advance state after a successful page response."""
        ...

    def should_stop(
        self,
        *,
        body: Any,
        headers: Any,
        items: list[Any],
        state: PageState,
        cfg: StrategyConfig,
    ) -> bool:
        """Return True when traversal should terminate after this page."""
        ...

    def to_checkpoint(self, state: PageState) -> dict[str, Any]:
        """Serialize traversal state into the checkpoint ``pagination`` slice."""
        ...

    def from_checkpoint(self, data: dict[str, Any]) -> PageState:
        """Restore traversal state from a checkpoint ``pagination`` slice."""
        ...


def is_short_or_empty_page(items: list[Any], page_size: int) -> bool:
    """True when the page is empty or shorter than the requested page size."""
    return len(items) < page_size
