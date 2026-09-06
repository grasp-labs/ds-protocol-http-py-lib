"""
**File:** ``offset.py``
**Region:** ``ds_protocol_http_py_lib/dataset/pagination/strategies/offset``

Offset / limit pagination strategy.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from ..base import is_short_or_empty_page
from ..enums import PaginationStrategy
from ..extract import extract_path
from ..inject import PageState, RequestSnapshot, inject_value
from ..registry import register

if TYPE_CHECKING:
    from ..settings import OffsetPaginationSettings


@register(PaginationStrategy.OFFSET)
class OffsetPaginationStrategy:
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
        out = inject_value(
            request,
            name=cfg.offset_param,
            value=state.values["offset"],
            location=cfg.inject_location,
        )
        return inject_value(
            out,
            name=cfg.limit_param,
            value=state.values["limit"],
            location=cfg.inject_location,
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
        total = extract_path(body, cfg.total_path)
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
