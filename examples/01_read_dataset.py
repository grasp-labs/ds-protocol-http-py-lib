"""
**File:** ``01_read_dataset.py``
**Region:** ``examples/01_read_dataset``

Example 01: Read a dataset over HTTP (GET) using ds-protocol-http-py-lib.
"""

from __future__ import annotations

from ds_common_logger_py_lib import Logger
from ds_resource_plugin_py_lib.common.resource.dataset.storage_format import DatasetStorageFormatType
from ds_resource_plugin_py_lib.common.serde.deserialize import PandasDeserializer

from ds_protocol_http_py_lib.dataset.http import HttpDataset, HttpDatasetTypedProperties
from ds_protocol_http_py_lib.linked_service.http import (
    HttpLinkedService,
    HttpLinkedServiceTypedProperties,
)

Logger()
logger = Logger.get_logger(__name__)


def main() -> None:
    try:
        # Replace these placeholders with your API details.
        host = "https://grasp-daas.com/api/state/v1"
        url = f"{host}/state/"

        linked_service = HttpLinkedService(
            typed_properties=HttpLinkedServiceTypedProperties(
                host=host,
                auth_type="OAuth2",
                client_id="",
                client_secret="",
                token_endpoint="https://auth.grasp-daas.com/oauth/token/",
            ),
        )

        dataset = HttpDataset(
            linked_service=linked_service,
            deserializer=PandasDeserializer(
                format=DatasetStorageFormatType.SEMI_STRUCTURED_JSON,
                kwargs={"record_path": "data"},
            ),
            typed_properties=HttpDatasetTypedProperties(
                method="GET",
                url=url,
                params={"limit": 100},
            ),
        )

        logger.info("Built HttpDataset (read)")
        logger.info("base_uri=%s", linked_service.base_uri)
        logger.info("url=%s", dataset.typed_properties.url)
        logger.info("method=%s", dataset.typed_properties.method)
        dataset.read(timeout=10)
        logger.info("Read complete")
        logger.info("next=%s", dataset.next)
        logger.info("cursor=%s", dataset.cursor)
        logger.info("content=%s", dataset.content)
    except Exception as exc:
        logger.exception("Read failed: %s", exc.__dict__)


if __name__ == "__main__":
    main()
