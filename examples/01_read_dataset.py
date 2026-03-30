"""
**File:** ``01_read_dataset.py``
**Region:** ``examples/01_read_dataset``

Example 01: Read a dataset over HTTP (GET) using ds-protocol-http-py-lib.

Demonstrates:
- Basic GET request with a static URL.
- GET request with path parameters interpolated into the URL template.
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
    """Read from a static URL."""
    linked_service = _make_linked_service()

    dataset = HttpDataset(
        id=uuid.uuid4(),
        name="example::dataset",
        version="1.0.0",
        linked_service=linked_service,
        settings=HttpDatasetSettings(
            method=HttpMethod.GET,
            url="http://example.com/data",
        ),
    )

    try:
        dataset.linked_service.connect()
        dataset.read()
    except ResourceException as exc:
        logger.error(f"Error reading dataset: {exc.__dict__}")
        return pd.DataFrame()

    return dataset.output


def main_with_path_params() -> pd.DataFrame:
    """Read from a URL template with path parameters.

    The ``{document_guid}`` placeholder in the URL is replaced with the value
    supplied in ``path_params`` before the request is sent.
    """
    linked_service = _make_linked_service()

    dataset = HttpDataset(
        id=uuid.uuid4(),
        name="example::dataset-with-path-params",
        version="1.0.0",
        linked_service=linked_service,
        settings=HttpDatasetSettings(
            method=HttpMethod.GET,
            url="http://example.com/documents/{document_guid}/original",
            path_params={"document_guid": "abc123"},
        ),
    )
    # Resolved URL → http://example.com/documents/abc123/original

    try:
        dataset.linked_service.connect()
        dataset.read()
        return dataset.output
    except ResourceException as exc:
        logger.error(f"Error reading dataset: {exc.__dict__}")
        return pd.DataFrame()


if __name__ == "__main__":
    logger.info("--- static URL ---")
    df = main()
    logger.info(df)

    logger.info("--- path params ---")
    df2 = main_with_path_params()
    logger.info(df2)
