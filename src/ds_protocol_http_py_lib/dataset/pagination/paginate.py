"""
**File:** ``paginate.py``
**Region:** ``ds_protocol_http_py_lib/dataset/pagination/paginate``

Paginate an HttpDataset read to exhaustion using the registered strategy.

Example:
    >>> dataset.settings.read.pagination = PaginationSettings(
    ...     strategy=PaginationStrategy.OFFSET,
    ...     items_path="data",
    ...     offset=OffsetPaginationSettings(page_size=100),
    ... )
    >>> dataset.read()  # delegates here when pagination is configured
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

import pandas as pd
from ds_common_logger_py_lib import Logger
from ds_resource_plugin_py_lib.common.resource.dataset.errors import ReadError
from ds_resource_plugin_py_lib.common.resource.errors import ResourceException
from ds_resource_plugin_py_lib.common.resource.linked_service.errors import (
    AuthenticationError,
    AuthorizationError,
    ConnectionError,
)

from ..incremental.watermark import commit as commit_incremental
from ..incremental.watermark import inject as inject_watermark
from .extract import extract_items, parse_json_body
from .inject import snapshot_from_settings
from .registry import get_strategy

if TYPE_CHECKING:
    from ..http import HttpDataset

logger = Logger.get_logger(__name__, package=True)


def _validate_checkpoint_strategy(
    checkpoint_slice: dict[str, Any] | None,
    expected: str,
) -> None:
    if checkpoint_slice is None:
        return
    if not isinstance(checkpoint_slice, dict):
        raise ValueError(
            f"checkpoint['pagination'] must be a dict (got {type(checkpoint_slice).__name__})",
        )
    actual = checkpoint_slice.get("strategy")
    if actual is not None and actual != expected:
        raise ValueError(
            f"Checkpoint pagination strategy '{actual}' does not match configured strategy '{expected}'",
        )


def _page_deserializer_input(
    *,
    response_content: bytes | str | None,
    items: list[Any],
    items_path: str,
) -> Any:
    """
    Build the payload passed to ``dataset.deserializer`` for one page.

    - ``items_path`` of ``$`` / ``""``: use raw ``response.content`` (same as a
      single-request read of a root array).
    - Otherwise: JSON-encode the extracted record list so pages concatenate as
      tabular rows (envelope fields are only used for pagination control).
    """
    if items_path in ("$", ""):
        return response_content
    return json.dumps(items).encode("utf-8")


def _concat_frames(frames: list[pd.DataFrame]) -> pd.DataFrame:
    """Concatenate page frames, or return an empty frame when none were fetched."""
    return pd.concat(frames, ignore_index=True) if frames else pd.DataFrame()


def paginate(dataset: HttpDataset[Any, Any]) -> None:
    """
    Follow all pages for ``dataset.settings.read.pagination`` and assign
    ``dataset.output``.

    Persists the ``pagination`` checkpoint slice while traversing so a failed
    mid-run can resume. On full success, commits the incremental watermark (if
    configured) and clears pagination state.

    Raises:
        AuthenticationError: If authentication fails.
        AuthorizationError: If authorization fails.
        ConnectionError: If the connection fails.
        ReadError: If pagination, parsing, or the HTTP call fails.
    """
    pagination = dataset.settings.read.pagination
    if pagination is None:
        raise ValueError("paginate() requires settings.read.pagination")

    frames: list[pd.DataFrame] = []
    settings = dataset.settings
    incremental = dataset.settings.read.incremental

    try:
        request = snapshot_from_settings(
            url=dataset._resolve_url(),
            method=settings.method,
            data=settings.data,
            json_body=settings.json,
            params=settings.params,
            headers=settings.headers,
            files=settings.files,
            map_files=dataset._map_files,
        )
        if incremental is not None:
            request = inject_watermark(request, dataset.checkpoint, incremental)

        strategy = get_strategy(pagination.strategy)
        cfg = pagination.strategy_config
        checkpoint_slice = dataset.checkpoint.get("pagination")
        _validate_checkpoint_strategy(checkpoint_slice, pagination.strategy.value)
        state = strategy.initial_state(cfg, checkpoint_slice)

        while pagination.max_pages is None or state.page_index < pagination.max_pages:
            page_request = strategy.inject(request, state, cfg)
            logger.debug(f"Sending {page_request.method} request to {page_request.url}")
            response = dataset.linked_service.connection.request(
                **page_request.to_request_kwargs(),
            )
            body = parse_json_body(response.content)
            items = extract_items(body, pagination.items_path)
            frames.append(
                dataset.deserializer(
                    _page_deserializer_input(
                        response_content=response.content,
                        items=items,
                        items_path=pagination.items_path,
                    ),
                )
                if dataset.deserializer
                else pd.DataFrame(items),
            )

            if strategy.should_stop(
                body=body,
                headers=response.headers,
                items=items,
                state=state,
                cfg=cfg,
            ):
                break

            state = strategy.advance(
                body=body,
                headers=response.headers,
                items=items,
                state=state,
                cfg=cfg,
            )
            dataset.checkpoint["pagination"] = strategy.to_checkpoint(state)
        else:
            raise ReadError(
                message=(f"Pagination exceeded max_pages={pagination.max_pages} for strategy '{pagination.strategy}'"),
                status_code=400,
                details={
                    "type": dataset.type.value,
                    "strategy": pagination.strategy,
                    "max_pages": pagination.max_pages,
                },
            )

        dataset.output = _concat_frames(frames)
        if incremental is not None:
            commit_incremental(dataset.checkpoint, dataset.output, incremental)
        else:
            dataset.checkpoint.pop("pagination", None)

    except (AuthenticationError, AuthorizationError, ConnectionError, ReadError):
        dataset.output = _concat_frames(frames)
        raise
    except ResourceException as exc:
        dataset.output = _concat_frames(frames)
        exc.details.update({"type": dataset.type.value})
        raise ReadError(
            message=exc.message,
            status_code=exc.status_code,
            details=exc.details,
        ) from exc
    except (AttributeError, KeyError, TypeError, ValueError) as exc:
        dataset.output = _concat_frames(frames)
        raise ReadError(
            message=str(exc),
            status_code=400,
            details={"type": dataset.type.value},
        ) from exc
