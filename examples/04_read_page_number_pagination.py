"""
**File:** ``04_read_page_number_pagination.py``
**Region:** ``examples/04_read_page_number_pagination``

Example 04: Page-number / page-size pagination (traversing scope).

Same checkpoint lifecycle as offset pagination: persist next page on mid-run
failure; clear pagination after a successful full read. ``start_page`` must
match the API (0- or 1-based).
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
    PageNumberPaginationSettings,
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
    """Read all pages with page-number pagination."""
    linked_service = _make_linked_service()

    dataset = HttpDataset(
        id=uuid.uuid4(),
        name="example::page-number-pagination",
        version="1.0.0",
        linked_service=linked_service,
        settings=HttpDatasetSettings(
            method=HttpMethod.GET,
            url="http://example.com/v1/customers",
            read=HttpReadSettings(
                pagination=PaginationSettings(
                    strategy=PaginationStrategy.PAGE_NUMBER,
                    items_path="results",
                    page_number=PageNumberPaginationSettings(
                        page_param="page",
                        page_size_param="per_page",
                        page_size=100,
                        start_page=1,
                        total_pages_path="total_pages",
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
        logger.error("Error reading dataset: %s (checkpoint=%s)", exc, dataset.checkpoint)
        return pd.DataFrame()

    return dataset.output


if __name__ == "__main__":
    logger.info("--- page_number pagination ---")
    logger.info(main())
