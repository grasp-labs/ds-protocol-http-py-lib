"""
**File:** ``http.py``
**Region:** ``ds_protocol_http_py_lib/dataset/http``

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

from dataclasses import dataclass, field
from typing import Any, Generic, Literal, NoReturn, TypeVar

import pandas as pd
from ds_resource_plugin_py_lib.common.resource.dataset import (
    DatasetStorageFormatType,
    DatasetTypedProperties,
    TabularDataset,
)
from ds_resource_plugin_py_lib.common.resource.linked_service.errors import (
    ConnectionError,
)
from ds_resource_plugin_py_lib.common.serde.deserialize import (
    DataDeserializer,
    PandasDeserializer,
)
from ds_resource_plugin_py_lib.common.serde.serialize import (
    DataSerializer,
    PandasSerializer,
)

from ..enums import ResourceKind
from ..linked_service.http import HttpLinkedService
from ..utils.http.provider import Http


@dataclass(kw_only=True)
class HttpDatasetTypedProperties(DatasetTypedProperties):
    method: Literal["GET", "POST", "PUT", "DELETE", "PATCH"] = "GET"

    url: str
    data: Any | None = None
    json: dict[str, Any] | None = None
    params: dict[str, Any] | None = None
    files: list[Any] | None = None
    headers: dict[str, Any] | None = None


HttpDatasetTypedPropertiesType = TypeVar(
    "HttpDatasetTypedPropertiesType",
    bound=HttpDatasetTypedProperties,
)
HttpLinkedServiceType = TypeVar(
    "HttpLinkedServiceType",
    bound=HttpLinkedService[Any],
)


@dataclass(kw_only=True)
class HttpDataset(
    TabularDataset[
        HttpLinkedServiceType,
        HttpDatasetTypedPropertiesType,
        DataSerializer,
        DataDeserializer,
    ],
    Generic[HttpLinkedServiceType, HttpDatasetTypedPropertiesType],
):
    linked_service: HttpLinkedServiceType
    typed_properties: HttpDatasetTypedPropertiesType

    serializer: DataSerializer | None = field(
        default_factory=lambda: PandasSerializer(format=DatasetStorageFormatType.JSON),
    )
    deserializer: DataDeserializer | None = field(
        default_factory=lambda: PandasDeserializer(format=DatasetStorageFormatType.JSON),
    )
    connection: Http | None = field(default=None, init=False)

    def __post_init__(self) -> None:
        if self.linked_service is not None:
            self.connection = self.linked_service.connect()

    @property
    def kind(self) -> ResourceKind:
        return ResourceKind.DATASET

    def create(self, **kwargs: Any) -> None:
        """
        Create data at the specified endpoint.

        Args:
            kwargs: Additional keyword arguments to pass to the request.
        """
        if self.connection is None:
            raise ConnectionError(
                message="Connection is not initialized.",
                code="NOT_INITIALIZED",
                status_code=503,
            )

        self.log.info(f"Sending {self.typed_properties.method} request to {self.typed_properties.url}")

        response = self.connection.request(
            method=self.typed_properties.method,
            url=self.typed_properties.url,
            data=self.typed_properties.data,
            json=self.typed_properties.json,
            files=self.typed_properties.files,
            params=self.typed_properties.params,
            headers=self.typed_properties.headers,
            **kwargs,
        )

        if response.content and self.deserializer:
            self.content = self.deserializer(response.content)
        else:
            self.content = pd.DataFrame()

    def read(self, **kwargs: Any) -> None:
        """
        Read data from the specified endpoint.

        Args:
            kwargs: Additional keyword arguments to pass to the request.
        """
        if self.connection is None:
            raise ConnectionError(message="Connection is not initialized.")

        self.log.info(f"Sending {self.typed_properties.method} request to {self.typed_properties.url}")

        response = self.connection.request(
            method=self.typed_properties.method,
            url=self.typed_properties.url,
            data=self.typed_properties.data,
            json=self.typed_properties.json,
            files=self.typed_properties.files,
            params=self.typed_properties.params,
            headers=self.typed_properties.headers,
            **kwargs,
        )

        if response.content and self.deserializer:
            self.content = self.deserializer(response.content)
            self.next = self.deserializer.get_next(response.content)
            if self.next:
                self.cursor = self.deserializer.get_end_cursor(response.content)
        else:
            self.next = False
            self.cursor = None
            self.content = pd.DataFrame()

    def delete(self, **kwargs: Any) -> NoReturn:
        raise NotImplementedError("Delete operation is not supported for Http datasets")

    def update(self, **kwargs: Any) -> NoReturn:
        raise NotImplementedError("Update operation is not supported for Http datasets")

    def rename(self, **kwargs: Any) -> NoReturn:
        raise NotImplementedError("Rename operation is not supported for Http datasets")
