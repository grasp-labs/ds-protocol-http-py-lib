"""
**File:** ``cursor.py``
**Region:** ``ds_protocol_http_py_lib/dataset/pagination/strategies/cursor``

Opaque cursor / token pagination strategy.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from ..enums import ExtractSource, InjectLocation, PaginationStrategy
from ..extract import extract_header, extract_path
from ..inject import PageState, RequestSnapshot, inject_value
from ..registry import register

if TYPE_CHECKING:
    from ..settings import CursorPaginationSettings


def _read_next_cursor(body: Any, headers: Any, cfg: CursorPaginationSettings) -> str | None:
    if cfg.cursor_source is ExtractSource.HEADER:
        return extract_header(headers, cfg.cursor_path)
    value = extract_path(body, cfg.cursor_path)
    if value is None or value == "":
        return None
    return value if isinstance(value, str) else str(value)


@register(PaginationStrategy.CURSOR)
class CursorPaginationStrategy:
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
        if cfg.page_size_param is not None and cfg.page_size is not None:
            out = inject_value(
                out,
                name=cfg.page_size_param,
                value=cfg.page_size,
                location=InjectLocation.QUERY,
            )
        cursor = state.values["cursor"]
        if cursor is not None:
            out = inject_value(
                out,
                name=cfg.cursor_param,
                value=cursor,
                location=cfg.cursor_location,
            )
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
            values={"cursor": nxt, "page_size": cfg.page_size},
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
