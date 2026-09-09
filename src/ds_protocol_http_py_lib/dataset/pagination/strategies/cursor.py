"""
**File:** ``cursor.py``
**Region:** ``ds_protocol_http_py_lib/dataset/pagination/strategies/cursor``

Opaque cursor / token page strategy.

When to use (arbitrary API)
    Pick this if the API **gives you the next position** — a token in the body
    or a header — and expects you to send it back, e.g. response
    ``{"data": [...], "next": "abc"}`` then request ``?cursor=abc``, or header
    ``Link: <...>; rel="next"`` / ``X-Next-Cursor``. You do not compute the
    next page; you echo whatever the server returned until it returns none.

    Prefer this over offset/page whenever both exist: tokens stay correct when
    the list mutates between calls. Use **offset** or **page_number** only when
    the API has no continuation token and documents numeric skip or page index
    instead.

    Note: mid-run resume stores the token in ``checkpoint["pagination"]``. If
    the API's tokens expire across process restarts, drain in one run or pair
    with incremental windowing — this strategy does not invent a durable
    watermark.

Intent
    Server-driven continuation. Stop when the next cursor is absent; raise if
    the cursor does not change (no progress).

Boundaries
    Owns cursor inject/extract, optional page-size query param, stop/progress
    checks, and mid-run ``checkpoint["pagination"]`` (``cursor``, ``page_size``,
    ``page_index``). Does not own HTTP, watermarks, or clearing pagination on
    success — :class:`Paginate` does.

Example::

    PaginationSettings(
        strategy=PaginationStrategy.CURSOR,
        items_path="data",
        cursor=CursorPaginationSettings(
            cursor_path="meta.next",
            cursor_param="cursor",
            page_size_param="limit",
            page_size=100,
        ),
    )
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from ....utils.http.request import InjectLocation, get_header
from ....utils.json_utils import get_path
from ..enums import ExtractSource, PaginationStrategy
from ..registry import register
from ..settings import CursorPaginationSettings
from .base import PageState, PaginationStrategyHandler

if TYPE_CHECKING:
    from ....utils.http.request import RequestSnapshot


def _read_next_cursor(
    body: Any,
    headers: Any,
    cfg: CursorPaginationSettings,
) -> str | None:
    if cfg.cursor_source is ExtractSource.HEADER:
        return get_header(headers, cfg.cursor_path)
    value = get_path(body, cfg.cursor_path)
    if value is None or value == "":
        return None
    return value if isinstance(value, str) else str(value)


@register(PaginationStrategy.CURSOR)
class CursorPaginationStrategy(PaginationStrategyHandler[CursorPaginationSettings]):
    """Opaque cursor pagination: echo the server token until it is absent."""

    def initial_state(
        self,
        cfg: CursorPaginationSettings,
        checkpoint_slice: dict[str, Any] | None,
    ) -> PageState:
        if checkpoint_slice is not None:
            return self.from_checkpoint(checkpoint_slice)
        return PageState(
            values={"cursor": None, "page_size": cfg.page_size},
            page_index=0,
        )

    def inject(
        self,
        request: RequestSnapshot,
        state: PageState,
        cfg: CursorPaginationSettings,
    ) -> RequestSnapshot:
        out = request.clone()
        # Page size is always a query parameter (independent of cursor_location).
        # Prefer the value restored from checkpoint / state over settings so
        # mid-run resume keeps the same page size.
        page_size = state.values.get("page_size", cfg.page_size)
        if cfg.page_size_param is not None and page_size is not None:
            out = out.inject(cfg.page_size_param, page_size, InjectLocation.QUERY)
        cursor = state.values["cursor"]
        if cursor is not None:
            out = out.inject(cfg.cursor_param, cursor, cfg.cursor_location)
        return out

    def advance(
        self,
        *,
        body: Any,
        headers: Any,
        items: list[Any],
        state: PageState,
        cfg: CursorPaginationSettings,
    ) -> PageState:
        del items
        previous = state.values["cursor"]
        nxt = _read_next_cursor(body, headers, cfg)
        if previous is not None and nxt == previous:
            raise ValueError("Cursor pagination made no progress (identical next cursor)")
        return PageState(
            values={
                "cursor": nxt,
                "page_size": state.values.get("page_size", cfg.page_size),
            },
            page_index=state.page_index + 1,
        )

    def should_stop(
        self,
        *,
        body: Any,
        headers: Any,
        items: list[Any],
        state: PageState,
        cfg: CursorPaginationSettings,
    ) -> bool:
        del items, state
        return _read_next_cursor(body, headers, cfg) is None

    def to_checkpoint(self, state: PageState) -> dict[str, Any]:
        return {
            "strategy": PaginationStrategy.CURSOR.value,
            "cursor": state.values["cursor"],
            "page_size": state.values["page_size"],
            "page_index": state.page_index,
        }

    def from_checkpoint(self, data: dict[str, Any]) -> PageState:
        return PageState(
            values={"cursor": data["cursor"], "page_size": data["page_size"]},
            page_index=data["page_index"],
        )
