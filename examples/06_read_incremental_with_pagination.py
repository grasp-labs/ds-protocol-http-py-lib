"""
**File:** ``06_read_incremental_with_pagination.py``
**Region:** ``examples/06_read_incremental_with_pagination``

Example 06: Incremental (shifting scope) + pagination (traversing scope).

These are separate concerns from the dataset contract:

- **Incremental / shifting scope** -- what counts as *new since last success*.
  Instruction lives in ``settings.read.incremental``; the watermark *value*
  lives in ``checkpoint["incremental"]``. The watermark advances **only**
  after a fully successful ``read()``.

- **Pagination / traversing scope** -- how to walk the *current* result window
  to completion inside one ``read()``. Instruction lives in
  ``settings.read.pagination``; the position lives in
  ``checkpoint["pagination"]`` for mid-run resume, and is **cleared** when the
  watermark advances on success.

Orchestrator sketch::

    if ds.supports_checkpoint:
        ds.checkpoint = state_store.load(ds.id)
    ds.read()
    if ds.supports_checkpoint:
        state_store.save(ds.id, ds.checkpoint)
"""

from __future__ import annotations

import logging
import os
import uuid

import pandas as pd
from dotenv import load_dotenv
from ds_common_logger_py_lib import Logger
from ds_resource_plugin_py_lib.common.resource.errors import ResourceException

from ds_protocol_http_py_lib.dataset.http import HttpDataset, HttpDatasetSettings
from ds_protocol_http_py_lib.dataset.incremental import IncrementalSettings
from ds_protocol_http_py_lib.dataset.pagination import (
    OffsetPaginationSettings,
    PaginationSettings,
    PaginationStrategy,
)
from ds_protocol_http_py_lib.dataset.http import HttpReadSettings
from ds_protocol_http_py_lib.enums import AuthType, HttpMethod
from ds_protocol_http_py_lib.utils.http.request import InjectLocation
from ds_protocol_http_py_lib.linked_service import OAuth2AuthSettings
from ds_protocol_http_py_lib.linked_service.http import (
    HttpLinkedService,
    HttpLinkedServiceSettings,
)

load_dotenv()

Logger.configure(level=logging.DEBUG)
logger = Logger.get_logger(__name__)


def _make_linked_service() -> HttpLinkedService:
    return HttpLinkedService(
        id=uuid.uuid4(),
        name="example::linked_service",
        version="1.0.0",
        settings=HttpLinkedServiceSettings(
            host="http://example.com",
            auth_type=AuthType.OAUTH2,
            headers={"Content-Type": "application/json"},
            oauth2=OAuth2AuthSettings(
                token_endpoint="http://example.com/oauth/token",
                client_id=os.environ["CLIENT_ID"],
                client_secret=os.environ["CLIENT_SECRET"],
            ),
        ),
    )


def main() -> pd.DataFrame:
    """Incremental watermark + offset pagination in one read."""
    linked_service = _make_linked_service()

    # Simulate orchestrator restore from a prior successful run.
    prior_checkpoint = {
        "incremental": {"watermark": "2024-01-01T00:00:00Z"},
        # No pagination key: previous run finished cleanly.
    }

    dataset = HttpDataset(
        id=uuid.uuid4(),
        name="example::incremental-with-pagination",
        version="1.0.0",
        linked_service=linked_service,
        settings=HttpDatasetSettings(
            method=HttpMethod.GET,
            url="http://example.com/v1/orders",
            read=HttpReadSettings(
                # Shifting scope: inject prior watermark as updated_since.
                incremental=IncrementalSettings(
                    param="updated_since",
                    location=InjectLocation.QUERY,
                    watermark_path="updated_at",
                ),
                # Traversing scope: walk pages inside this incremental window.
                pagination=PaginationSettings(
                    strategy=PaginationStrategy.OFFSET,
                    items_path="data",
                    offset=OffsetPaginationSettings(
                        offset_param="offset",
                        limit_param="limit",
                        page_size=50,
                        initial_offset=0,
                        total_path="meta.total",
                    ),
                ),
            ),
        ),
        checkpoint=dict(prior_checkpoint),
    )

    try:
        dataset.linked_service.connect()
        dataset.read()
        # Success example:
        #   {"incremental": {"watermark": "<max updated_at from output>"}}
        # Pagination key is gone -- traversal resets for the next run.
        logger.info("checkpoint after success: %s", dataset.checkpoint)
    except ResourceException as exc:
        # Failure example:
        #   incremental watermark UNCHANGED
        #   pagination holds next offset for resume within the same window
        logger.error(
            "Error reading dataset: %s (checkpoint=%s)", exc, dataset.checkpoint
        )
        return pd.DataFrame()

    return dataset.output


if __name__ == "__main__":
    logger.info("--- incremental + pagination ---")
    logger.info(main())
