"""
**File:** ``01_read_dataset.py``
**Region:** ``examples/01_read_dataset``

Example 01: Read a dataset over HTTP (GET) using ds-protocol-http-py-lib.
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


logger = Logger.get_logger(__name__,package = True)


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
            method="GET",
            url="",
        ),
    )

    frames = []
    try:
        dataset.linked_service.connect()
        while dataset.next:
            dataset.read()
            logger.debug("Dataset next: %s", dataset.next)
            logger.debug("Schema: %s", dataset.schema)
            frames.append(dataset.output)
            break
    except ResourceException as exc:
        logger.error(f"Error reading dataset: {exc.__dict__}")
        return pd.DataFrame()

    return pd.concat(frames)


if __name__ == "__main__":
    df = main()
    logger.info(df)
