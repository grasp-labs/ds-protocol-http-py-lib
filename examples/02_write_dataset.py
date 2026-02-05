"""
**File:** ``02_write_dataset.py``
**Region:** ``examples/02_write_dataset``

Example 02: Write a dataset over HTTP (POST) using ds-protocol-http-py-lib.
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


def main() -> pd.DataFrame:
    linked_service = HttpLinkedService(
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

    dataset = HttpDataset(
        id=uuid.uuid4(),
        name="example::dataset",
        version="1.0.0",
        linked_service=linked_service,
        settings=HttpDatasetSettings(
            method=HttpMethod.POST,
            url="http://example.com/data",
        ),
    )

    try:
        dataset.linked_service.connect()
        dataset.create()
        logger.debug("Dataset next: %s", dataset.next)
        logger.debug("Schema: %s", dataset.schema)
        return dataset.output
    except ResourceException as exc:
        logger.error(f"Error reading dataset: {exc.__dict__}")
        return pd.DataFrame()


if __name__ == "__main__":
    df = main()
    logger.debug(df)
