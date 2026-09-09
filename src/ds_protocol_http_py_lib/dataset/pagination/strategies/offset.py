"""
**File:** ``offset.py``
**Region:** ``ds_protocol_http_py_lib/dataset/pagination/strategies/offset``

Offset / limit page strategy.

When to use (arbitrary API)
    Pick this if the API asks for a **numeric skip** into the list, e.g.
    ``?offset=0&limit=100``, ``?skip=200&take=50``, ``from=100&size=100``.
    You (the client) compute the next window: ``offset += limit``.

    Prefer **cursor** instead when the same API also offers a next-token —
    offsets break under inserts/deletes between pages (skipped / duplicated
    rows). Prefer **page_number** if the API speaks in page indexes, not row
    offsets (``?page=2&per_page=50``).

Intent
    Client-derived windows over a list. Stop on a short/empty page, or when
    ``offset + limit >= total`` if ``total_path`` is set.

Boundaries
    Owns page params, stop logic, and mid-run ``checkpoint["pagination"]``
    (``offset``, ``limit``, ``page_index``). Does not own HTTP, watermarks, or
    clearing pagination on success — :class:`Paginate` does.

Example::

    PaginationSettings(
        strategy=PaginationStrategy.OFFSET,
        items_path="data",
        offset=OffsetPaginationSettings(
            page_size=100,
            total_path="meta.total",  # optional
        ),
    )
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from ....utils.json_utils import get_path
from ..enums import PaginationStrategy
from ..registry import register
from ..settings import OffsetPaginationSettings
from .base import PageState, PaginationStrategyHandler, is_short_or_empty_page

if TYPE_CHECKING:
    from ....utils.http.request import RequestSnapshot


@register(PaginationStrategy.OFFSET)
class OffsetPaginationStrategy(PaginationStrategyHandler[OffsetPaginationSettings]):
    """Client-derived offset pagination: ``offset(n+1) = offset(n) + limit``."""

    def initial_state(
        self,
        cfg: OffsetPaginationSettings,
        checkpoint_slice: dict[str, Any] | None,
    ) -> PageState:
        if checkpoint_slice is not None:
            return self.from_checkpoint(checkpoint_slice)
        return PageState(
            values={"offset": cfg.initial_offset, "limit": cfg.page_size},
            page_index=0,
        )

    def inject(
        self,
        request: RequestSnapshot,
        state: PageState,
        cfg: OffsetPaginationSettings,
    ) -> RequestSnapshot:
        out = request.inject(
            cfg.offset_param,
            state.values["offset"],
            cfg.inject_location,
        )
        return out.inject(
            cfg.limit_param,
            state.values["limit"],
            cfg.inject_location,
        )

    def advance(
        self,
        *,
        body: Any,
        headers: Any,
        items: list[Any],
        state: PageState,
        cfg: OffsetPaginationSettings,
    ) -> PageState:
        del body, headers, items
        return PageState(
            values={
                "offset": state.values["offset"] + state.values["limit"],
                "limit": cfg.page_size,
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
        cfg: OffsetPaginationSettings,
    ) -> bool:
        del headers
        if is_short_or_empty_page(items, cfg.page_size):
            return True
        if cfg.total_path is None:
            return False
        total = get_path(body, cfg.total_path)
        return total is not None and state.values["offset"] + state.values["limit"] >= int(total)

    def to_checkpoint(self, state: PageState) -> dict[str, Any]:
        return {
            "strategy": PaginationStrategy.OFFSET.value,
            "offset": state.values["offset"],
            "limit": state.values["limit"],
            "page_index": state.page_index,
        }

    def from_checkpoint(self, data: dict[str, Any]) -> PageState:
        return PageState(
            values={"offset": data["offset"], "limit": data["limit"]},
            page_index=data["page_index"],
        )
