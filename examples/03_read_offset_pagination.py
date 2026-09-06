"""
**File:** ``03_read_offset_pagination.py``
**Region:** ``examples/03_read_offset_pagination``

Example 03: Offset / limit pagination (traversing scope).

Pagination walks pages *within one read* until exhaustion. That is traversing
scope -- not incremental shifting across runs.

Checkpoint rules illustrated here:
- After each successful page, ``checkpoint["pagination"]`` holds the *next*
  offset so a mid-run failure can resume without re-fetching completed pages.
- After a fully successful read, pagination state is cleared.
- No incremental watermark is configured, so nothing is written under
  ``checkpoint["incremental"]``.
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
from ds_protocol_http_py_lib.dataset.pagination import (
    OffsetPaginationSettings,
    PaginationSettings,
    PaginationStrategy,
)
from ds_protocol_http_py_lib.dataset.http import HttpReadSettings
from ds_protocol_http_py_lib.enums import AuthType, HttpMethod
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
    """Read all pages with offset/limit pagination."""
    linked_service = _make_linked_service()

    dataset = HttpDataset(
        id=uuid.uuid4(),
        name="example::offset-pagination",
        version="1.0.0",
        linked_service=linked_service,
        settings=HttpDatasetSettings(
            method=HttpMethod.GET,
            url="http://example.com/v1/orders",
            read=HttpReadSettings(
                pagination=PaginationSettings(
                    strategy=PaginationStrategy.OFFSET,
                    items_path="data",
                    max_pages=1000,
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
    )

    # supports_checkpoint is True because pagination is configured (resume).
    assert dataset.supports_checkpoint is True

    try:
        dataset.linked_service.connect()
        dataset.read()
        # Success → pagination slice cleared for the next run.
        # dataset.checkpoint == {}  (or no "pagination" key)
        logger.info("checkpoint after success: %s", dataset.checkpoint)
    except ResourceException as exc:
        # Failure mid-traversal → keep last safe next offset.
        # e.g. {"pagination": {"strategy": "offset", "offset": 50, "limit": 50, ...}}
        logger.error("Error reading dataset: %s (checkpoint=%s)", exc, dataset.checkpoint)
        return pd.DataFrame()

    return dataset.output


if __name__ == "__main__":
    logger.info("--- offset pagination ---")
    logger.info(main())
