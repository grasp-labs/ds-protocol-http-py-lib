"""
**File:** ``__init__.py``
**Region:** ``ds_protocol_http_py_lib/dataset``

HTTP Dataset

This module implements a dataset for HTTP APIs.

Example:
    >>> dataset = HttpDataset(
    ...     deserializer=PandasDeserializer(format=DatasetStorageFormatType.JSON),
    ...     serializer=PandasSerializer(format=DatasetStorageFormatType.JSON),
    ...     typed_properties=HttpDatasetTypedProperties(
    ...         url="https://api.example.com/data",
    ...         method="GET",
    ...     ),
    ...     linked_service=HttpLinkedService(
    ...         typed_properties=HttpLinkedServiceTypedProperties(
    ...             host="https://api.example.com",
    ...             auth_type="OAuth2",
    ...         ),
    ...     ),
    ... )
    >>> dataset.read()
    >>> data = dataset.content
"""

from .http import HttpDataset, HttpDatasetTypedProperties

__all__ = [
    "HttpDataset",
    "HttpDatasetTypedProperties",
]
