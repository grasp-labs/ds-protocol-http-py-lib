"""
**File:** ``paginate.py``
**Region:** ``ds_protocol_http_py_lib/dataset/pagination/paginate``

Paginate composer: pulls page strategy + incremental rules + checkpoint together.

Example:
    >>> dataset.settings.read.pagination = PaginationSettings(
    ...     strategy=PaginationStrategy.OFFSET,
    ...     items_path="data",
    ...     offset=OffsetPaginationSettings(page_size=100),
    ... )
    >>> Paginate.from_dataset(dataset).run(dataset)
"""

from __future__ import annotations

import json
from copy import deepcopy
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

from ...utils.http.request import RequestSnapshot
from ...utils.json_utils import get_list, parse_json
from ..incremental import NoIncrementalRules, get_rules
from .registry import get_strategy

if TYPE_CHECKING:
    from ..http import HttpDataset
    from ..incremental.rules import IncrementalRules
    from ..incremental.settings import IncrementalSettings
    from .settings import PaginationSettings
    from .strategies.base import PaginationStrategyHandler

logger = Logger.get_logger(__name__, package=True)


class Paginate:
    """
    Composer for a paginated ``HttpDataset.read``.

    Resolves a registered page strategy and optional incremental ruleset, then
    runs prepare → drain → commit. Strategy hooks supply page variation only;
    this class owns HTTP, checkpoint pagination slice, and error mapping.
    """

    def __init__(
        self,
        strategy: PaginationStrategyHandler[Any],
        pagination: PaginationSettings,
        incremental_rules: IncrementalRules,
        incremental: IncrementalSettings | None,
    ) -> None:
        self.strategy = strategy
        self.pagination = pagination
        self.incremental_rules = incremental_rules
        self.incremental = incremental

    @classmethod
    def from_dataset(cls, dataset: HttpDataset[Any, Any]) -> Paginate:
        """Build from ``dataset.settings.read`` and the strategy / rules registries."""
        pagination = dataset.settings.read.pagination
        if pagination is None:
            raise ValueError("Paginate requires settings.read.pagination")

        incremental = dataset.settings.read.incremental
        if incremental is not None:
            rules: IncrementalRules = get_rules(incremental.strategy)
        else:
            rules = NoIncrementalRules()

        return cls(
            strategy=get_strategy(pagination.strategy),
            pagination=pagination,
            incremental_rules=rules,
            incremental=incremental,
        )

    def run(self, dataset: HttpDataset[Any, Any]) -> None:
        """
        Prepare → drain → assign ``output`` / checkpoint.

        On full success: clear ``checkpoint["pagination"]``, then incremental
        ``commit`` if configured. On failure: assign partial ``output``, keep
        mid-run pagination resume, hold watermark.
        """
        frames: list[pd.DataFrame] = []
        try:
            request = self.incremental_rules.prepare(
                self._snapshot(dataset),
                dataset.checkpoint,
                self.incremental,
            )
            self.drain(dataset, request, frames)
            dataset.output = self._concat_frames(frames)
            dataset.checkpoint.pop("pagination", None)
            self.incremental_rules.commit(
                dataset.checkpoint,
                dataset.output,
                self.incremental,
            )
        except (AuthenticationError, AuthorizationError, ConnectionError, ReadError):
            dataset.output = self._concat_frames(frames)
            raise
        except ResourceException as exc:
            dataset.output = self._concat_frames(frames)
            exc.details.update({"type": dataset.type.value})
            raise ReadError(
                message=exc.message,
                status_code=exc.status_code,
                details=exc.details,
            ) from exc
        except (AttributeError, KeyError, TypeError, ValueError) as exc:
            dataset.output = self._concat_frames(frames)
            raise ReadError(
                message=str(exc),
                status_code=400,
                details={"type": dataset.type.value},
            ) from exc

    def drain(
        self,
        dataset: HttpDataset[Any, Any],
        request: RequestSnapshot,
        frames: list[pd.DataFrame] | None = None,
    ) -> list[pd.DataFrame]:
        """
        Page loop via strategy hooks; write mid-run ``checkpoint["pagination"]``.

        Appends page frames to ``frames`` (created if omitted) so callers retain
        partial output when this method raises mid-drain.

        Raises:
            ReadError: If ``max_pages`` is exceeded without a natural stop.
        """
        if frames is None:
            frames = []

        pagination = self.pagination
        strategy = self.strategy
        cfg = pagination.strategy_config
        checkpoint_slice = dataset.checkpoint.get("pagination")
        self._validate_checkpoint_strategy(
            checkpoint_slice,
            pagination.strategy.value,
        )
        state = strategy.initial_state(cfg, checkpoint_slice)

        while pagination.max_pages is None or state.page_index < pagination.max_pages:
            page_request = strategy.inject(request, state, cfg)
            logger.debug(f"Sending {page_request.method} request to {page_request.url}")
            response = dataset.linked_service.connection.request(
                **page_request.to_request_kwargs(),
            )
            body = parse_json(response.content)
            items = get_list(body, pagination.items_path)
            frames.append(
                dataset.deserializer(
                    self._page_deserializer_input(
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

        return frames

    def _snapshot(self, dataset: HttpDataset[Any, Any]) -> RequestSnapshot:
        """Build an isolated request copy from dataset settings."""
        settings = dataset.settings
        return RequestSnapshot(
            url=dataset._resolve_url(),
            method=settings.method,
            data=deepcopy(settings.data),
            json=deepcopy(settings.json),
            params=deepcopy(settings.params),
            headers=deepcopy(settings.headers),
            files=dataset._map_files(settings.files),
        )

    @staticmethod
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

    @staticmethod
    def _page_deserializer_input(
        *,
        response_content: bytes | str | None,
        items: list[Any],
        items_path: str,
    ) -> Any:
        """
        Build the payload passed to ``dataset.deserializer`` for one page.

        - ``items_path`` of ``$`` / ``""``: use raw ``response.content``.
        - Otherwise: JSON-encode the extracted record list.
        """
        if items_path in ("$", ""):
            return response_content
        return json.dumps(items).encode("utf-8")

    @staticmethod
    def _concat_frames(frames: list[pd.DataFrame]) -> pd.DataFrame:
        """Concatenate page frames, or return an empty frame when none were fetched."""
        return pd.concat(frames, ignore_index=True) if frames else pd.DataFrame()
