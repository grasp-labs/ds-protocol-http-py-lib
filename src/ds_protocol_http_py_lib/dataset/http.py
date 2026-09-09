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

from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any, Generic, NoReturn, TypeVar

import pandas as pd
from ds_common_logger_py_lib import Logger
from ds_common_serde_py_lib import Serializable
from ds_resource_plugin_py_lib.common.resource.dataset import (
    DatasetSettings,
    DatasetStorageFormatType,
    TabularDataset,
)
from ds_resource_plugin_py_lib.common.resource.dataset.errors import (
    CreateError,
    ReadError,
)
from ds_resource_plugin_py_lib.common.resource.errors import (
    NotSupportedError,
    ResourceException,
)
from ds_resource_plugin_py_lib.common.resource.linked_service.errors import (
    AuthenticationError,
    AuthorizationError,
    ConnectionError,
)
from ds_resource_plugin_py_lib.common.serde.deserialize import PandasDeserializer
from ds_resource_plugin_py_lib.common.serde.serialize import PandasSerializer

from ..enums import HttpMethod, ResourceType
from ..linked_service.http import HttpLinkedService
from ..models import Files
from .incremental.settings import IncrementalSettings
from .pagination.paginate import Paginate
from .pagination.settings import PaginationSettings

logger = Logger.get_logger(__name__, package=True)


@dataclass(kw_only=True)
class HttpReadSettings(Serializable):
    """
    Operation-scoped settings for ``HttpDataset.read()``.

    - ``pagination`` — traversing scope within one read (absent = single request).
    - ``incremental`` — watermark ruleset consulted by Paginate (not a separate gate).
    """

    pagination: PaginationSettings | None = None
    """Pagination mechanism. ``None`` means a single request with no page loop."""

    incremental: IncrementalSettings | None = None
    """Incremental watermark rules for Paginate. Ignored when pagination is unset."""


@dataclass(kw_only=True)
class HttpDatasetSettings(DatasetSettings):
    """Settings for an HTTP dataset request."""

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

    files: list[Files] | None = None
    """The multipart files to send with the request."""

    headers: dict[str, Any] | None = None
    """The headers to send with the request."""

    path_params: dict[str, Any] | None = None
    """Path parameters to interpolate into the URL template using {param} syntax.

    Example:
        url="https://api.example.com/documents/{document_guid}/original"
        path_params={"document_guid": "abc123"}
        # → https://api.example.com/documents/abc123/original
    """

    read: HttpReadSettings = field(default_factory=HttpReadSettings)
    """Read-scoped settings: pagination (traversing) and incremental (shifting)."""


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
    """
    Tabular dataset backed by an HTTP API.

    ``read()`` behavior is gated by ``settings.read``:

    - pagination configured → :class:`Paginate` (optional incremental rules)
    - otherwise → original single-request read
    """

    linked_service: HttpLinkedServiceType
    """Linked service used to issue authenticated HTTP requests."""

    settings: HttpDatasetSettingsType
    """Request and read-scoped configuration."""

    serializer: PandasSerializer | None = field(
        default_factory=lambda: PandasSerializer(format=DatasetStorageFormatType.JSON),
    )
    """Serializer used when writing payloads (``create``)."""

    deserializer: PandasDeserializer | None = field(
        default_factory=lambda: PandasDeserializer(format=DatasetStorageFormatType.JSON),
    )
    """Deserializer used to materialize ``output`` from response bodies."""

    @property
    def type(self) -> ResourceType:
        """Resource type discriminator."""
        return ResourceType.DATASET

    @property
    def supports_checkpoint(self) -> bool:
        """True when pagination (mid-run resume / optional watermark) is configured."""
        return self.settings.read.pagination is not None

    def _resolve_url(self) -> str:
        """Resolve the URL by substituting any path parameters."""
        if self.settings.path_params is not None:
            try:
                return self.settings.url.format(**self.settings.path_params)
            except (KeyError, ValueError) as exc:
                # Normalize all URL template resolution issues into a ResourceException
                details: dict[str, Any] = {
                    "type": self.type.value,
                    "url_template": self.settings.url,
                    "path_params": self.settings.path_params,
                }
                message = "Failed to resolve URL: missing path parameter"
                if isinstance(exc, ValueError):
                    message = "Failed to resolve URL: invalid URL template"
                    details["template_error"] = str(exc)
                else:
                    details["missing_path_param"] = str(exc)
                raise ResourceException(
                    message=message,
                    status_code=400,
                    details=details,
                ) from exc
        return self.settings.url

    def create(self) -> None:
        """
        Create data at the specified endpoint (single request).

        Raises:
            AuthenticationError: If authentication fails.
            AuthorizationError: If authorization fails.
            ConnectionError: If the connection fails.
            CreateError: If the create call fails.
        """
        try:
            url = self._resolve_url()
            logger.debug(f"Sending {self.settings.method} request to {url}")
            response = self.linked_service.connection.request(
                method=self.settings.method,
                url=url,
                data=self.settings.data,
                json=self.settings.json,
                files=self._map_files(self.settings.files),
                params=self.settings.params,
                headers=self.settings.headers,
            )
        except (AuthenticationError, AuthorizationError, ConnectionError):
            raise
        except ResourceException as exc:
            exc.details.update({"type": self.type.value})
            raise CreateError(
                message=exc.message,
                status_code=exc.status_code,
                details=exc.details,
            ) from exc

        if response.content and self.deserializer:
            self.output = self.deserializer(response.content)
        else:
            self.output = pd.DataFrame()

    def read(self) -> None:
        """
        Read data from the specified endpoint.

        When ``settings.read.pagination`` is set, runs
        ``Paginate.from_dataset(self).run(self)``. Otherwise issues one request.

        Raises:
            AuthenticationError: If authentication fails.
            AuthorizationError: If authorization fails.
            ConnectionError: If the connection fails.
            ReadError: If the read call or pagination fails.
        """
        if self.settings.read.pagination is not None:
            Paginate.from_dataset(self).run(self)
            return

        try:
            url = self._resolve_url()
            logger.debug(f"Sending {self.settings.method} request to {url}")
            response = self.linked_service.connection.request(
                method=self.settings.method,
                url=url,
                data=self.settings.data,
                json=self.settings.json,
                files=self._map_files(self.settings.files),
                params=self.settings.params,
                headers=self.settings.headers,
            )
        except (AuthenticationError, AuthorizationError, ConnectionError):
            raise
        except ResourceException as exc:
            exc.details.update({"type": self.type.value})
            raise ReadError(
                message=exc.message,
                status_code=exc.status_code,
                details=exc.details,
            ) from exc

        if response.content and self.deserializer:
            self.output = self.deserializer(response.content)
        else:
            self.output = pd.DataFrame()

    def delete(self) -> NoReturn:
        """
        Delete entity using http.
        """
        raise NotSupportedError("Delete operation is not supported for Http datasets")

    def update(self) -> NoReturn:
        """
        Update entity using http.
        """
        raise NotSupportedError("Update operation is not supported for Http datasets")

    def rename(self) -> NoReturn:
        """
        Rename entity using http.
        """
        raise NotSupportedError("Rename operation is not supported for Http datasets")

    def upsert(self) -> NoReturn:
        """
        Upsert entity using http.
        """
        raise NotSupportedError("Upsert operation is not supported for Http datasets")

    def purge(self) -> NoReturn:
        """
        Purge entity using http.
        """
        raise NotSupportedError("Purge operation is not supported for Http datasets")

    def list(self) -> NoReturn:
        """
        List entity using http.
        """
        raise NotSupportedError("List operation is not supported for Http datasets")

    def _map_files(self, files: Sequence[Files] | None) -> Any:
        """
        Convert typed `Files` descriptors into `requests` compatible `files=...`.

        `HttpDatasetSettings.files` is expected to already be deserialized
        into the correct typed model, so this method focuses purely on the
        `requests` shape conversion.
        """
        if not files:
            return None

        return [(file.field, file.to_requests_file_tuple()) for file in files]

    def close(self) -> None:
        """
        Close the dataset.
        """
        self.linked_service.close()
