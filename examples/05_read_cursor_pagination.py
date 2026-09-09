"""
**File:** ``05_read_cursor_pagination.py``
**Region:** ``examples/05_read_cursor_pagination``

Example 05: Opaque cursor / token pagination (traversing scope).

The cursor is echoed untouched. Termination is an absent / null / empty next
token. Cursor tokens are often single-use or time-limited: they belong to
intra-read traversal (and optional mid-run resume), not to inter-run
incremental state. On success the pagination slice is cleared.
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
    CursorPaginationSettings,
    ExtractSource,
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
    """Read all pages with cursor pagination."""
    linked_service = _make_linked_service()

    dataset = HttpDataset(
        id=uuid.uuid4(),
        name="example::cursor-pagination",
        version="1.0.0",
        linked_service=linked_service,
        settings=HttpDatasetSettings(
            method=HttpMethod.GET,
            url="http://example.com/v1/events",
            read=HttpReadSettings(
                pagination=PaginationSettings(
                    strategy=PaginationStrategy.CURSOR,
                    items_path="items",
                    cursor=CursorPaginationSettings(
                        cursor_path="response_metadata.next_cursor",
                        cursor_source=ExtractSource.BODY,
                        cursor_param="cursor",
                        page_size_param="limit",
                        page_size=200,
                    ),
                ),
            ),
        ),
    )

    try:
        dataset.linked_service.connect()
        dataset.read()
        logger.info("checkpoint after success: %s", dataset.checkpoint)
    except ResourceException as exc:
        # Mid-run failure may leave {"pagination": {"cursor": "<next>", ...}}
        logger.error("Error reading dataset: %s (checkpoint=%s)", exc, dataset.checkpoint)
        return pd.DataFrame()

    return dataset.output


if __name__ == "__main__":
    logger.info("--- cursor pagination ---")
    logger.info(main())
