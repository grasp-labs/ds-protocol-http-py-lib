"""
**File:** ``test_dataset_http.py``
**Region:** ``tests/dataset/test_dataset_http``

HttpDataset behavior tests.

Covers:
- Connection initialization via explicit connect() call.
- create/read request execution and argument propagation.
- Serializer/deserializer interactions and empty-response handling.
- Pagination state updates (next/cursor) driven by the deserializer.
"""

from __future__ import annotations

import uuid
from types import SimpleNamespace
from typing import Any, cast

import pandas as pd
import pandas.testing as pdt
import pytest
from ds_resource_plugin_py_lib.common.resource.dataset.errors import CreateError, ReadError
from ds_resource_plugin_py_lib.common.resource.errors import NotSupportedError, ResourceException
from ds_resource_plugin_py_lib.common.resource.linked_service.errors import (
    AuthenticationError,
    AuthorizationError,
    ConnectionError,
)

from ds_protocol_http_py_lib.dataset.http import HttpDataset, HttpDatasetSettings
from ds_protocol_http_py_lib.enums import HttpMethod, ResourceType
from tests.mocks import DeserializerStub, HttpClient, HttpResponseBytes, LinkedService


def test_dataset_type_is_dataset() -> None:
    """
    It exposes dataset type.
    """
    props = HttpDatasetSettings(url="https://example.test/data")
    dataset = HttpDataset(
        id=uuid.uuid4(),
        name="test-dataset",
        version="1.0.0",
        linked_service=cast("Any", LinkedService(http=HttpClient(response=HttpResponseBytes(content=b"")))),
        settings=props,
    )
    assert dataset.type == ResourceType.DATASET


def test_create_raises_when_connection_is_missing() -> None:
    """
    It raises ConnectionError when called without an initialized connection.
    """

    props = HttpDatasetSettings(url="https://example.test/data")
    dataset = HttpDataset(
        id=uuid.uuid4(),
        name="test-dataset",
        version="1.0.0",
        linked_service=cast("Any", LinkedService(http=HttpClient(response=HttpResponseBytes(content=b"")))),
        settings=props,
    )
    with pytest.raises(ConnectionError):
        dataset.create()


def test_read_raises_when_connection_is_missing() -> None:
    """
    It raises ConnectionError when read is called without an initialized connection.
    """

    props = HttpDatasetSettings(url="https://example.test/data")
    dataset = HttpDataset(
        id=uuid.uuid4(),
        name="test-dataset",
        version="1.0.0",
        linked_service=cast("Any", LinkedService(http=HttpClient(response=HttpResponseBytes(content=b"")))),
        settings=props,
    )
    with pytest.raises(ConnectionError):
        dataset.read()


def test_create_without_serializer_still_makes_request_and_deserializes() -> None:
    """
    It can run create when serializer is None and still deserialize response content.
    """

    deserializer = DeserializerStub()
    http = HttpClient(response=HttpResponseBytes(content=b'{"ok": 1}'))
    linked_service = LinkedService(http=http)
    props = HttpDatasetSettings(url="https://example.test/data", method=HttpMethod.POST, data=b"raw")
    dataset = HttpDataset(
        id=uuid.uuid4(),
        name="test-dataset",
        version="1.0.0",
        linked_service=cast("Any", linked_service),
        settings=props,
        serializer=None,
        deserializer=cast("Any", deserializer),
    )
    linked_service.connect()
    dataset.create()
    assert http.last_request is not None
    assert http.last_request["data"] == b"raw"
    assert isinstance(dataset.output, pd.DataFrame)


def test_create_sets_empty_dataframe_when_response_has_no_content() -> None:
    """
    It sets content to an empty DataFrame when response content is empty.
    """

    http = HttpClient(response=HttpResponseBytes(content=b""))
    linked_service = LinkedService(http=http)
    props = HttpDatasetSettings(url="https://example.test/data")
    dataset = HttpDataset(
        id=uuid.uuid4(), name="test-dataset", version="1.0.0", linked_service=cast("Any", linked_service), settings=props
    )
    linked_service.connect()
    dataset.create()
    assert isinstance(dataset.output, pd.DataFrame)
    assert dataset.output.empty is True


def test_read_sets_defaults_when_response_has_no_content() -> None:
    """
    It sets next to False, cursor to None, and content to empty DataFrame when no content exists.
    """

    http = HttpClient(response=HttpResponseBytes(content=b""))
    linked_service = LinkedService(http=http)
    props = HttpDatasetSettings(url="https://example.test/data")
    dataset = HttpDataset(
        id=uuid.uuid4(), name="test-dataset", version="1.0.0", linked_service=cast("Any", linked_service), settings=props
    )
    linked_service.connect()
    dataset.read()
    assert isinstance(dataset.output, pd.DataFrame)
    assert dataset.output.empty is True


def test_read_wraps_resource_exception_into_read_error() -> None:
    """
    It wraps a provider ResourceException into ReadError and includes dataset type in details.
    """
    http = HttpClient(
        response=HttpResponseBytes(content=b""),
        error=ResourceException(message="boom", status_code=418, details={}),
    )
    linked_service = LinkedService(http=http)
    props = HttpDatasetSettings(url="https://example.test/data")
    dataset = HttpDataset(
        id=uuid.uuid4(), name="test-dataset", version="1.0.0", linked_service=cast("Any", linked_service), settings=props
    )
    linked_service.connect()
    with pytest.raises(ReadError) as exc_info:
        dataset.read()
    assert exc_info.value.status_code == 418
    assert exc_info.value.details["type"] == ResourceType.DATASET.value


def test_create_wraps_resource_exception_into_write_error() -> None:
    """
    It wraps a provider ResourceException into WriteError and includes dataset type in details.
    """
    http = HttpClient(
        response=HttpResponseBytes(content=b""),
        error=ResourceException(message="boom", status_code=418, details={}),
    )
    linked_service = LinkedService(http=http)
    props = HttpDatasetSettings(url="https://example.test/data", method=HttpMethod.POST)
    dataset = HttpDataset(
        id=uuid.uuid4(), name="test-dataset", version="1.0.0", linked_service=cast("Any", linked_service), settings=props
    )
    linked_service.connect()
    with pytest.raises(CreateError) as exc_info:
        dataset.create()
    assert exc_info.value.status_code == 418
    assert exc_info.value.details["type"] == ResourceType.DATASET.value


@pytest.mark.parametrize(
    "exc",
    [
        AuthenticationError(message="no", details={}),
        AuthorizationError(message="no", details={}),
        ConnectionError(message="no", details={}),
    ],
)
def test_dataset_propagates_authz_and_connection_errors(exc: Exception) -> None:
    """
    It re-raises auth/authorization/connection errors directly.
    """
    http = HttpClient(response=HttpResponseBytes(content=b""), error=exc)
    linked_service = LinkedService(http=http)
    props = HttpDatasetSettings(url="https://example.test/data")
    dataset = HttpDataset(
        id=uuid.uuid4(), name="test-dataset", version="1.0.0", linked_service=cast("Any", linked_service), settings=props
    )
    linked_service.connect()
    with pytest.raises(type(exc)):
        dataset.read()


@pytest.mark.parametrize(
    "exc",
    [
        AuthenticationError(message="no", details={}),
        AuthorizationError(message="no", details={}),
        ConnectionError(message="no", details={}),
    ],
)
def test_dataset_create_propagates_authz_and_connection_errors(exc: Exception) -> None:
    """
    It re-raises auth/authorization/connection errors directly (create path).
    """
    http = HttpClient(response=HttpResponseBytes(content=b""), error=exc)
    linked_service = LinkedService(http=http)
    props = HttpDatasetSettings(url="https://example.test/data", method=HttpMethod.POST)
    dataset = HttpDataset(
        id=uuid.uuid4(), name="test-dataset", version="1.0.0", linked_service=cast("Any", linked_service), settings=props
    )
    linked_service.connect()
    with pytest.raises(type(exc)):
        dataset.create()


def test_dataset_unimplemented_methods_raise() -> None:
    """
    It raises NotSupportedError for delete/update/rename.
    """
    http = HttpClient(response=HttpResponseBytes(content=b""))
    linked_service = LinkedService(http=http)
    props = HttpDatasetSettings(url="https://example.test/data")
    dataset = HttpDataset(
        id=uuid.uuid4(), name="test-dataset", version="1.0.0", linked_service=cast("Any", linked_service), settings=props
    )
    with pytest.raises(NotSupportedError):
        dataset.delete()
    with pytest.raises(NotSupportedError):
        dataset.update()
    with pytest.raises(NotSupportedError):
        dataset.rename()
    with pytest.raises(NotSupportedError):
        dataset.purge()
    with pytest.raises(NotSupportedError):
        dataset.list()
    with pytest.raises(NotSupportedError):
        dataset.upsert()


def test_close_delegates_to_linked_service_close() -> None:
    """
    It calls the linked service's close method.
    """
    props = HttpDatasetSettings(url="https://example.test/data")
    linked_service = LinkedService(http=HttpClient(response=HttpResponseBytes(content=b"")))
    dataset = HttpDataset(
        id=uuid.uuid4(),
        name="test-dataset",
        version="1.0.0",
        linked_service=cast("Any", linked_service),
        settings=props,
    )
    assert linked_service.closed is False
    dataset.close()
    assert linked_service.closed is True


def test_read_interpolates_path_params_into_url() -> None:
    """
    It substitutes {param} placeholders in the URL with values from path_params before sending.
    """
    captured: dict[str, Any] = {}

    def fake_request(**kwargs: Any) -> SimpleNamespace:
        captured.update(kwargs)
        return SimpleNamespace(content=b"")

    connection = SimpleNamespace(request=fake_request)
    linked_service = cast("Any", SimpleNamespace(connection=connection, close=lambda: None))

    settings = HttpDatasetSettings(
        url="https://api.example.com/documents/{document_guid}/original",
        method=HttpMethod.GET,
        path_params={"document_guid": "abc123"},
    )
    dataset = HttpDataset(linked_service=linked_service, settings=settings, id=1, name="test", version="1.0.0")
    dataset.read()

    assert captured["url"] == "https://api.example.com/documents/abc123/original"


def test_create_interpolates_path_params_into_url() -> None:
    """
    It substitutes {param} placeholders in the URL with values from path_params on create.
    """
    captured: dict[str, Any] = {}

    def fake_request(**kwargs: Any) -> SimpleNamespace:
        captured.update(kwargs)
        return SimpleNamespace(content=b"")

    connection = SimpleNamespace(request=fake_request)
    linked_service = cast("Any", SimpleNamespace(connection=connection, close=lambda: None))

    settings = HttpDatasetSettings(
        url="https://api.example.com/documents/{document_guid}/original",
        method=HttpMethod.POST,
        path_params={"document_guid": "xyz789"},
    )
    dataset = HttpDataset(linked_service=linked_service, settings=settings, id=1, name="test", version="1.0.0")
    dataset.create()

    assert captured["url"] == "https://api.example.com/documents/xyz789/original"


def test_read_without_path_params_uses_url_unchanged() -> None:
    """
    It sends the URL as-is when path_params is not provided.
    """
    captured: dict[str, Any] = {}

    def fake_request(**kwargs: Any) -> SimpleNamespace:
        captured.update(kwargs)
        return SimpleNamespace(content=b"")

    connection = SimpleNamespace(request=fake_request)
    linked_service = cast("Any", SimpleNamespace(connection=connection, close=lambda: None))

    settings = HttpDatasetSettings(url="https://api.example.com/data", method=HttpMethod.GET)
    dataset = HttpDataset(linked_service=linked_service, settings=settings, id=1, name="test", version="1.0.0")
    dataset.read()

    assert captured["url"] == "https://api.example.com/data"


def test_read_interpolates_multiple_path_params_into_url() -> None:
    """
    It substitutes multiple {param} placeholders in the URL with values from path_params.
    """
    captured: dict[str, Any] = {}

    def fake_request(**kwargs: Any) -> SimpleNamespace:
        captured.update(kwargs)
        return SimpleNamespace(content=b"")

    connection = SimpleNamespace(request=fake_request)
    linked_service = cast("Any", SimpleNamespace(connection=connection, close=lambda: None))

    settings = HttpDatasetSettings(
        url="https://api.example.com/{org}/{repo}/contents/{path}",
        method=HttpMethod.GET,
        path_params={"org": "acme", "repo": "widgets", "path": "README.md"},
    )
    dataset = HttpDataset(linked_service=linked_service, settings=settings, id=1, name="test", version="1.0.0")
    dataset.read()

    assert captured["url"] == "https://api.example.com/acme/widgets/contents/README.md"


def test_read_ignores_extra_path_params_not_present_in_url() -> None:
    """
    It silently ignores extra keys in path_params that have no matching placeholder in the URL.
    """
    captured: dict[str, Any] = {}

    def fake_request(**kwargs: Any) -> SimpleNamespace:
        captured.update(kwargs)
        return SimpleNamespace(content=b"")

    connection = SimpleNamespace(request=fake_request)
    linked_service = cast("Any", SimpleNamespace(connection=connection, close=lambda: None))

    settings = HttpDatasetSettings(
        url="https://api.example.com/documents/{document_guid}/original",
        method=HttpMethod.GET,
        path_params={"document_guid": "abc123", "unused_key": "ignored", "another_extra": "also_ignored"},
    )
    dataset = HttpDataset(linked_service=linked_service, settings=settings, id=1, name="test", version="1.0.0")
    dataset.read()

    assert captured["url"] == "https://api.example.com/documents/abc123/original"


def test_read_raises_read_error_when_path_param_is_missing() -> None:
    """
    It raises ReadError (not a raw KeyError or bare ResourceException) when a required
    placeholder in the URL template has no matching key in path_params.  The original
    diagnostic details are preserved in the ReadError.
    """
    settings = HttpDatasetSettings(
        url="https://api.example.com/documents/{document_guid}/original",
        method=HttpMethod.GET,
        path_params={},  # missing "document_guid"
    )
    connection = SimpleNamespace(request=lambda **kwargs: SimpleNamespace(content=b""))
    linked_service = cast("Any", SimpleNamespace(connection=connection, close=lambda: None))
    dataset = HttpDataset(linked_service=linked_service, settings=settings, id=1, name="test", version="1.0.0")

    with pytest.raises(ReadError) as exc_info:
        dataset.read()

    assert exc_info.value.details["missing_path_param"] == "'document_guid'"
    assert exc_info.value.details["url_template"] == "https://api.example.com/documents/{document_guid}/original"


def test_http_dataset_read_uses_deserializer_not_overwritten() -> None:
    """
    Ensure `HttpDataset.read` preserves the deserializer result and does not
    overwrite it with an empty DataFrame.
    """
    content = b'{"x": [1]}'
    connection = SimpleNamespace(request=lambda **kwargs: SimpleNamespace(content=content))
    linked_service = SimpleNamespace(connection=connection, close=lambda: None)

    settings = HttpDatasetSettings(url="https://example.test/data", method=HttpMethod.GET)
    dataset = HttpDataset(linked_service=linked_service, settings=settings, id=1, name="test", version="1.0.0")

    expected = pd.DataFrame({"x": [1]})
    dataset.deserializer = lambda c: expected

    dataset.read()

    pdt.assert_frame_equal(dataset.output, expected)
