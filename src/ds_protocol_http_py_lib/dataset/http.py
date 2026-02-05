"""
**File:** ``http.py``
**Region:** ``ds_protocol_http_py_lib/dataset/http``

HTTP Dataset

This module implements a dataset for HTTP APIs.

Example:
    >>> from ds_protocol_http_py_lib.enums import AuthType
    >>> from ds_protocol_http_py_lib.linked_service import OAuth2AuthSettings
    >>> dataset = HttpDataset(
    ...     deserializer=PandasDeserializer(format=DatasetStorageFormatType.JSON),
    ...     serializer=PandasSerializer(format=DatasetStorageFormatType.JSON),
    ...     settings=HttpDatasetSettings(
    ...         url="https://api.example.com/data",
    ...         method=HttpMethod.GET,
    ...     ),
    ...     linked_service=HttpLinkedService(
    ...         settings=HttpLinkedServiceSettings(
    ...             host="api.example.com",
    ...             auth_type=AuthType.OAUTH2,
    ...             oauth2=OAuth2AuthSettings(
    ...                 token_endpoint="https://auth.example.com/token",
    ...                 client_id="my-client",
    ...                 client_secret="secret",
    ...             ),
    ...         ),
    ...     ),
    ... )
    >>> dataset.read()
    >>> data = dataset.output
"""

from dataclasses import dataclass, field
from typing import Any, Generic, NoReturn, TypeVar

import pandas as pd
from ds_common_logger_py_lib import Logger
from ds_resource_plugin_py_lib.common.resource.dataset import (
    DatasetSettings,
    DatasetStorageFormatType,
    TabularDataset,
)
from ds_resource_plugin_py_lib.common.resource.dataset.errors import (
    CreateError,
    ReadError,
)
from ds_resource_plugin_py_lib.common.resource.errors import ResourceException
from ds_resource_plugin_py_lib.common.resource.linked_service.errors import (
    AuthenticationError,
    AuthorizationError,
    ConnectionError,
)
from ds_resource_plugin_py_lib.common.serde.deserialize import PandasDeserializer
from ds_resource_plugin_py_lib.common.serde.serialize import PandasSerializer

from ..enums import HttpMethod, ResourceType
from ..linked_service.http import HttpLinkedService

logger = Logger.get_logger(__name__, package=True)


@dataclass(kw_only=True)
class HttpDatasetSettings(DatasetSettings):
    """
    Settings for HTTP dataset.
    """

    method: HttpMethod = HttpMethod.GET
    """The HTTP method to use."""

    url: str
    """The URL to send the request to."""

    data: Any | None = None
    """The data to send with the request."""

    json: dict[str, Any] | None = None
    """The JSON data to send with the request."""

    params: dict[str, Any] | None = None
    """The parameters to send with the request."""

    files: list[Any] | None = None
    """The files to send with the request."""

    headers: dict[str, Any] | None = None
    """The headers to send with the request."""


HttpDatasetSettingsType = TypeVar(
    "HttpDatasetSettingsType",
    bound=HttpDatasetSettings,
)
HttpLinkedServiceType = TypeVar(
    "HttpLinkedServiceType",
    bound=HttpLinkedService[Any],
)


@dataclass(kw_only=True)
class HttpDataset(
    TabularDataset[
        HttpLinkedServiceType,
        HttpDatasetSettingsType,
        PandasSerializer,
        PandasDeserializer,
    ],
    Generic[HttpLinkedServiceType, HttpDatasetSettingsType],
):
    linked_service: HttpLinkedServiceType
    settings: HttpDatasetSettingsType

    serializer: PandasSerializer | None = field(
        default_factory=lambda: PandasSerializer(format=DatasetStorageFormatType.JSON),
    )
    deserializer: PandasDeserializer | None = field(
        default_factory=lambda: PandasDeserializer(format=DatasetStorageFormatType.JSON),
    )

    @property
    def type(self) -> ResourceType:
        return ResourceType.DATASET

    def create(self, **kwargs: Any) -> None:
        """
        Create data at the specified endpoint.

        Args:
            kwargs: Additional keyword arguments to pass to the request.

        Raises:
            AuthenticationError: If the authentication fails.
            AuthorizationError: If the authorization fails.
            ConnectionError: If the connection fails.
            CreateError: If the create error occurs.
        """
        if self.linked_service.connection is None:
            raise ConnectionError(message="Connection is not initialized.")

        logger.debug(f"Sending {self.settings.method} request to {self.settings.url}")

        try:
            response = self.linked_service.connection.request(
                method=self.settings.method,
                url=self.settings.url,
                data=self.settings.data,
                json=self.settings.json,
                files=self.settings.files,
                params=self.settings.params,
                headers=self.settings.headers,
                **kwargs,
            )
        except (AuthenticationError, AuthorizationError, ConnectionError) as exc:
            raise exc
        except ResourceException as exc:
            exc.details.update({"type": self.type.value})
            raise CreateError(
                message=exc.message,
                status_code=exc.status_code,
                details=exc.details,
            ) from exc

        if response.content and self.deserializer:
            self.output = self.deserializer(response.content)
            self._set_schema(self.output)
        else:
            self.output = pd.DataFrame()

    def read(self, **kwargs: Any) -> None:
        """
        Read data from the specified endpoint.

        Args:
            kwargs: Additional keyword arguments to pass to the request.

        Raises:
            AuthenticationError: If the authentication fails.
            AuthorizationError: If the authorization fails.
            ConnectionError: If the connection fails.
            ReadError: If the read error occurs.
        """
        if self.linked_service.connection is None:
            raise ConnectionError(message="Connection is not initialized.")

        logger.debug(f"Sending {self.settings.method} request to {self.settings.url}")

        try:
            response = self.linked_service.connection.request(
                method=self.settings.method,
                url=self.settings.url,
                data=self.settings.data,
                json=self.settings.json,
                files=self.settings.files,
                params=self.settings.params,
                headers=self.settings.headers,
                **kwargs,
            )
        except (AuthenticationError, AuthorizationError, ConnectionError) as exc:
            raise exc
        except ResourceException as exc:
            exc.details.update({"type": self.type.value})
            raise ReadError(
                message=exc.message,
                status_code=exc.status_code,
                details=exc.details,
            ) from exc

        if response.content and self.deserializer:
            self.output = self.deserializer(response.content)
            self._set_schema(self.output)
            self.next = self.deserializer.get_next(response.content)
            if self.next:
                self.cursor = self.deserializer.get_end_cursor(response.content)
        else:
            self.next = False
            self.cursor = None
            self.output = pd.DataFrame()

    def delete(self, **kwargs: Any) -> NoReturn:
        raise NotImplementedError("Delete operation is not supported for Http datasets")

    def update(self, **kwargs: Any) -> NoReturn:
        raise NotImplementedError("Update operation is not supported for Http datasets")

    def rename(self, **kwargs: Any) -> NoReturn:
        raise NotImplementedError("Rename operation is not supported for Http datasets")

    def close(self) -> None:
        """
        Close the dataset.
        """
        self.linked_service.close()

    def _set_schema(self, content: pd.DataFrame) -> None:
        """
        Set the schema from the content.

        Args:
            content: The content to set the schema from.
        """
        self.schema = {
            str(col): str(dtype) for col, dtype in content.convert_dtypes(dtype_backend="pyarrow").dtypes.to_dict().items()
        }
