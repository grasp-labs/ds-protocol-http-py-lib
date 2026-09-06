"""
**File:** ``settings.py``
**Region:** ``ds_protocol_http_py_lib/dataset/pagination/settings``

Pagination settings nests for HttpDataset read configuration.

Example:
    >>> PaginationSettings(
    ...     strategy=PaginationStrategy.OFFSET,
    ...     items_path="data",
    ...     offset=OffsetPaginationSettings(page_size=100, total_path="meta.total"),
    ... )
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Union, cast

from ds_common_serde_py_lib import Serializable

from .enums import ExtractSource, InjectLocation, PaginationStrategy

StrategyConfig = Union[
    "OffsetPaginationSettings",
    "PageNumberPaginationSettings",
    "CursorPaginationSettings",
]


@dataclass(kw_only=True)
class OffsetPaginationSettings(Serializable):
    """Configuration for offset / limit pagination."""

    offset_param: str = "offset"
    """Query/body/header parameter name for the offset."""

    limit_param: str = "limit"
    """Query/body/header parameter name for the page size."""

    page_size: int = 100
    """Number of records requested per page."""

    initial_offset: int = 0
    """Offset used for the first page when no checkpoint exists."""

    total_path: str | None = None
    """Optional body path to a total record count used for termination."""

    inject_location: InjectLocation = InjectLocation.QUERY
    """Where offset and limit are injected on the request."""


@dataclass(kw_only=True)
class PageNumberPaginationSettings(Serializable):
    """Configuration for page-number / page-size pagination."""

    page_param: str = "page"
    """Parameter name for the page ordinal."""

    page_size_param: str = "per_page"
    """Parameter name for the page size."""

    page_size: int = 100
    """Number of records requested per page."""

    start_page: int = 1
    """First page ordinal (0- or 1-based, must match the API)."""

    total_pages_path: str | None = None
    """Optional body path to a total page count used for termination."""

    inject_location: InjectLocation = InjectLocation.QUERY
    """Where page and page size are injected on the request."""


@dataclass(kw_only=True)
class CursorPaginationSettings(Serializable):
    """Configuration for opaque cursor / token pagination."""

    cursor_path: str
    """Body path or header name where the next cursor is read."""

    cursor_source: ExtractSource = ExtractSource.BODY
    """Whether the cursor is extracted from the response body or a header."""

    cursor_param: str = "cursor"
    """Parameter / header / body key used to inject the cursor."""

    cursor_location: InjectLocation = InjectLocation.QUERY
    """Where the cursor is injected on the next request."""

    page_size_param: str | None = None
    """Optional page-size query parameter name (always injected as QUERY)."""

    page_size: int | None = None
    """Optional requested page size (sent with ``page_size_param``)."""


@dataclass(kw_only=True)
class PaginationSettings(Serializable):
    """
    Declared pagination mechanism and strategy-specific nests.

    Provide the nest matching ``strategy`` (same pattern as auth nests on
    ``HttpLinkedServiceSettings``). Other nests should be omitted from the
    payload; only the selected nest is read at runtime.
    """

    strategy: PaginationStrategy
    """Pagination mechanism. Declared explicitly; never inferred."""

    max_pages: int | None = None
    """
    Optional client-side safety ceiling on pages fetched per ``read()``.

    ``None`` (default) means no ceiling — keep paging until the strategy
    signals stop (short page, total count, empty cursor, …). Set an ``int``
    only when you want a hard guard against runaway loops.
    """

    items_path: str = "data"
    """Path to the record array in the response body. Use ``$`` for a root array."""

    offset: OffsetPaginationSettings | None = None
    """Required when ``strategy`` is ``offset``."""

    page_number: PageNumberPaginationSettings | None = None
    """Required when ``strategy`` is ``page_number``."""

    cursor: CursorPaginationSettings | None = None
    """Required when ``strategy`` is ``cursor``."""

    def __post_init__(self) -> None:
        # Surfaces as DeserializationError when constructed via Serializable.deserialize.
        if self._selected_nest() is None:
            raise ValueError(
                f"PaginationSettings.{self.strategy.value} is required when strategy is '{self.strategy.value}'",
            )

    def _selected_nest(self) -> StrategyConfig | None:
        return {
            PaginationStrategy.OFFSET: self.offset,
            PaginationStrategy.PAGE_NUMBER: self.page_number,
            PaginationStrategy.CURSOR: self.cursor,
        }[self.strategy]

    @property
    def strategy_config(self) -> StrategyConfig:
        """Strategy-specific nest for ``strategy`` (guaranteed by ``__post_init__``)."""
        return cast("StrategyConfig", self._selected_nest())
