"""
**File:** ``02_write_dataset.py``
**Region:** ``examples/02_write_dataset``

Example 02: Write to a dataset over HTTP (POST) using ds-protocol-http-py-lib.
"""

from __future__ import annotations

from ds_common_logger_py_lib import Logger

from ds_protocol_http_py_lib.dataset.http import HttpDataset, HttpDatasetTypedProperties
from ds_protocol_http_py_lib.linked_service.http import (
    HttpLinkedService,
    HttpLinkedServiceTypedProperties,
)

Logger()
logger = Logger.get_logger(__name__)


def main() -> None:
    try:
        host = "https://api.example.com"
        url = f"{host}/v1/items"

        linked_service = HttpLinkedService(
            typed_properties=HttpLinkedServiceTypedProperties(
                host=host,
                auth_type="NoAuth",
            ),
        )

        dataset = HttpDataset(
            linked_service=linked_service,
            typed_properties=HttpDatasetTypedProperties(
                method="POST",
                url=url,
                json={"hello": "world"},
            ),
        )

        logger.info("Built HttpDataset (write)")
        logger.info("base_uri=%s", linked_service.base_uri)
        logger.info("url=%s", dataset.typed_properties.url)
        logger.info("method=%s", dataset.typed_properties.method)
        logger.info("json=%s", dataset.typed_properties.json)
        dataset.create()
        logger.info("Create complete")
        logger.info("content=%s", dataset.content)
    except Exception as exc:
        logger.exception("Write failed: %s", exc)


if __name__ == "__main__":
    main()
