"""
**File:** ``02_write_dataset.py``
**Region:** ``examples/02_write_dataset``

Example 02: Write a dataset over HTTP (POST) using ds-protocol-http-py-lib.
"""

from __future__ import annotations

import pandas as pd
from ds_common_logger_py_lib import Logger
from ds_resource_plugin_py_lib.common.resource.errors import ResourceException

from ds_protocol_http_py_lib.dataset.http import HttpDataset, HttpDatasetSettings
from ds_protocol_http_py_lib.linked_service.http import (
    HttpLinkedService,
    HttpLinkedServiceSettings,
)

logger = Logger.get_logger(__name__, package=True)


def main() -> pd.DataFrame:
    linked_service = HttpLinkedService(
        settings=HttpLinkedServiceSettings(
            host="",
            auth_type="OAuth2",
            headers={"Content-Type": "application/json"},
            client_id="",
            client_secret="",
            token_endpoint="",
        ),
    )

    dataset = HttpDataset(
        linked_service=linked_service,
        settings=HttpDatasetSettings(
            method="POST",
            url="",
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
