"""
**File:** ``page_number.py``
**Region:** ``ds_protocol_http_py_lib/dataset/pagination/strategies/page_number``

Page-number / page-size strategy.

When to use (arbitrary API)
    Pick this if the API asks for a **page index**, e.g. ``?page=1&per_page=50``,
    ``?pageNumber=2&pageSize=25``, ``?p=0&size=100``. You advance
    ``page += 1``. Set ``start_page`` to whatever the API uses (0 or 1).

    Prefer **offset** if the API uses row skip/limit instead of page numbers.
    Prefer **cursor** if the API returns a next-token — safer when rows are
    inserted/deleted between requests.

Intent
    Client-derived page ordinals. Stop on a short/empty page, or when
    ``page >= total_pages`` if ``total_pages_path`` is set.

Boundaries
    Owns page params, stop logic, and mid-run ``checkpoint["pagination"]``
    (``page``, ``page_size``, ``page_index``). Does not own HTTP, watermarks, or
    clearing pagination on success — :class:`Paginate` does.

Example::

    PaginationSettings(
        strategy=PaginationStrategy.PAGE_NUMBER,
        items_path="results",
        page_number=PageNumberPaginationSettings(
            page_size=50,
            start_page=1,
            total_pages_path="meta.pages",  # optional
        ),
    )
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from ....utils.json_utils import get_path
from ..enums import PaginationStrategy
from ..registry import register
from ..settings import PageNumberPaginationSettings
from .base import PageState, PaginationStrategyHandler, is_short_or_empty_page

if TYPE_CHECKING:
    from ....utils.http.request import RequestSnapshot


@register(PaginationStrategy.PAGE_NUMBER)
class PageNumberPaginationStrategy(PaginationStrategyHandler[PageNumberPaginationSettings]):
    """Client-derived page ordinal pagination: ``page(n+1) = page(n) + 1``."""

    def initial_state(
        self,
        cfg: PageNumberPaginationSettings,
        checkpoint_slice: dict[str, Any] | None,
    ) -> PageState:
        if checkpoint_slice is not None:
            return self.from_checkpoint(checkpoint_slice)
        return PageState(
            values={"page": cfg.start_page, "page_size": cfg.page_size},
            page_index=0,
        )

    def inject(
        self,
        request: RequestSnapshot,
        state: PageState,
        cfg: PageNumberPaginationSettings,
    ) -> RequestSnapshot:
        out = request.inject(
            cfg.page_param,
            state.values["page"],
            cfg.inject_location,
        )
        return out.inject(
            cfg.page_size_param,
            state.values["page_size"],
            cfg.inject_location,
        )

    def advance(
        self,
        *,
        body: Any,
        headers: Any,
        items: list[Any],
        state: PageState,
        cfg: PageNumberPaginationSettings,
    ) -> PageState:
        del body, headers, items
        return PageState(
            values={
                "page": state.values["page"] + 1,
                "page_size": cfg.page_size,
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
        cfg: PageNumberPaginationSettings,
    ) -> bool:
        del headers
        if is_short_or_empty_page(items, cfg.page_size):
            return True
        if cfg.total_pages_path is None:
            return False
        total_pages = get_path(body, cfg.total_pages_path)
        return total_pages is not None and state.values["page"] >= int(total_pages)

    def to_checkpoint(self, state: PageState) -> dict[str, Any]:
        return {
            "strategy": PaginationStrategy.PAGE_NUMBER.value,
            "page": state.values["page"],
            "page_size": state.values["page_size"],
            "page_index": state.page_index,
        }

    def from_checkpoint(self, data: dict[str, Any]) -> PageState:
        return PageState(
            values={"page": data["page"], "page_size": data["page_size"]},
            page_index=data["page_index"],
        )
