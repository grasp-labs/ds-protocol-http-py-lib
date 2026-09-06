"""
**File:** ``page_number.py``
**Region:** ``ds_protocol_http_py_lib/dataset/pagination/strategies/page_number``

Page-number / page-size pagination strategy.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from ..base import is_short_or_empty_page
from ..enums import PaginationStrategy
from ..extract import extract_path
from ..inject import PageState, RequestSnapshot, inject_value
from ..registry import register

if TYPE_CHECKING:
    from ..settings import PageNumberPaginationSettings


@register(PaginationStrategy.PAGE_NUMBER)
class PageNumberPaginationStrategy:
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
        out = inject_value(
            request,
            name=cfg.page_param,
            value=state.values["page"],
            location=cfg.inject_location,
        )
        return inject_value(
            out,
            name=cfg.page_size_param,
            value=state.values["page_size"],
            location=cfg.inject_location,
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
        total_pages = extract_path(body, cfg.total_pages_path)
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
