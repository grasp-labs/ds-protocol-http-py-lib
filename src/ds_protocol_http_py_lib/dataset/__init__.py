"""
**File:** ``__init__.py``
**Region:** ``ds_protocol_http_py_lib/dataset``

HTTP Dataset

This module implements a dataset for HTTP APIs.

Example:
    >>> dataset = HttpDataset(
    ...     id=uuid.uuid4(),
    ...     name="example::dataset",
    ...     version="1.0.0",
    ...     deserializer=PandasDeserializer(format=DatasetStorageFormatType.JSON),
    ...     serializer=PandasSerializer(format=DatasetStorageFormatType.JSON),
    ...     settings=HttpDatasetSettings(
    ...         url="https://api.example.com/data",
    ...         method=HttpMethod.GET,
    ...     ),
    ...     linked_service=HttpLinkedService(
    ...         id=uuid.uuid4(),
    ...         name="example::linked_service",
    ...         version="1.0.0",
    ...         settings=HttpLinkedServiceSettings(
    ...             host="https://api.example.com",
    ...             auth_type=AuthType.OAUTH2,
    ...             oauth2=OAuth2AuthSettings(
    ...                 token_endpoint="https://api.example.com/token",
    ...                 client_id="my-client",
    ...                 client_secret="secret",
    ...             ),
    ...         ),
    ...     ),
    ... )
    >>> dataset.read()
    >>> data = dataset.output
"""

from .http import HttpDataset, HttpDatasetSettings

__all__ = [
    "HttpDataset",
    "HttpDatasetSettings",
]
