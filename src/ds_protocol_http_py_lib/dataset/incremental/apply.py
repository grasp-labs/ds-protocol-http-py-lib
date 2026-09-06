"""
**File:** ``apply.py``
**Region:** ``ds_protocol_http_py_lib/dataset/incremental/apply``

Single-request read with incremental watermark inject/commit (no pagination).

Example:
    >>> dataset.settings.read.incremental = IncrementalSettings(
    ...     param="updated_since",
    ...     watermark_path="updated_at",
    ... )
    >>> dataset.read()  # delegates here when only incremental is configured
"""

from __future__ import annotations

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

from ..pagination.inject import snapshot_from_settings
from .watermark import commit, inject

if TYPE_CHECKING:
    from ..http import HttpDataset

logger = Logger.get_logger(__name__, package=True)


def apply(dataset: HttpDataset[Any, Any]) -> None:
    """
    Inject watermark, issue one request, assign ``dataset.output``, commit watermark.

    Raises:
        AuthenticationError: If authentication fails.
        AuthorizationError: If authorization fails.
        ConnectionError: If the connection fails.
        ReadError: If the HTTP call fails.
    """
    incremental = dataset.settings.read.incremental
    if incremental is None:
        raise ValueError("apply() requires settings.read.incremental")

    try:
        settings = dataset.settings
        request = inject(
            snapshot_from_settings(
                url=dataset._resolve_url(),
                method=settings.method,
                data=settings.data,
                json_body=settings.json,
                params=settings.params,
                headers=settings.headers,
                files=settings.files,
                map_files=dataset._map_files,
            ),
            dataset.checkpoint,
            incremental,
        )
        logger.debug(f"Sending {request.method} request to {request.url}")
        response = dataset.linked_service.connection.request(**request.to_request_kwargs())
    except (AuthenticationError, AuthorizationError, ConnectionError):
        raise
    except ResourceException as exc:
        exc.details.update({"type": dataset.type.value})
        raise ReadError(
            message=exc.message,
            status_code=exc.status_code,
            details=exc.details,
        ) from exc

    if response.content and dataset.deserializer:
        dataset.output = dataset.deserializer(response.content)
    else:
        dataset.output = pd.DataFrame()

    commit(dataset.checkpoint, dataset.output, incremental)
