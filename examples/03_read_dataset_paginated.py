"""
**File:** ``03_read_dataset_paginated.py``
**Region:** ``examples/03_read_dataset_paginated``

Example 03: Read a paginated HTTP dataset (GET) using ds-protocol-http-py-lib.

Demonstrates:
- Read pagination driven by ``limit`` and ``offset`` request params.
- How the dataset concatenates multiple pages into a single DataFrame.
"""

from __future__ import annotations

import logging
import uuid

import pandas as pd
from ds_common_logger_py_lib import Logger
from ds_resource_plugin_py_lib.common.resource.errors import ResourceException

from ds_protocol_http_py_lib.dataset.http import HttpDataset, HttpDatasetSettings
from ds_protocol_http_py_lib.enums import AuthType, HttpMethod
from ds_protocol_http_py_lib.linked_service import OAuth2AuthSettings
from ds_protocol_http_py_lib.linked_service.http import (
    HttpLinkedService,
    HttpLinkedServiceSettings,
)

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
                client_id="******",
                client_secret="******",
            ),
        ),
    )


def main() -> pd.DataFrame:
    """
    Read a dataset using limit/offset pagination.

    The API must honor ``limit`` and ``offset`` in the query params. The dataset keeps
    requesting pages until the returned page is shorter than the configured limit.
    """
    linked_service = _make_linked_service()

    dataset = HttpDataset(
        id=uuid.uuid4(),
        name="example::paginated-dataset",
        version="1.0.0",
        linked_service=linked_service,
        settings=HttpDatasetSettings(
            method=HttpMethod.GET,
            url="http://example.com/items",
            paginate=True,
            params={
                "limit": 100,
                "offset": 0,
                "status": "active",
            },
        ),
    )

    try:
        dataset.linked_service.connect()
        dataset.read()
    except ResourceException as exc:
        logger.error(f"Error reading dataset: {exc.__dict__}")
        return pd.DataFrame()

    return dataset.output


if __name__ == "__main__":
    logger.info("--- paginated read ---")
    df = main()
    logger.info(df)
