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

from typing import Any, cast

import pandas as pd
import pytest
from ds_resource_plugin_py_lib.common.resource.dataset.errors import ReadError, WriteError
from ds_resource_plugin_py_lib.common.resource.errors import ResourceException
from ds_resource_plugin_py_lib.common.resource.linked_service.errors import (
    AuthenticationError,
    AuthorizationError,
    ConnectionError,
)

from ds_protocol_http_py_lib.dataset.http import HttpDataset, HttpDatasetTypedProperties
from ds_protocol_http_py_lib.enums import ResourceKind
from tests.mocks import DeserializerStub, HttpClient, HttpResponseBytes, LinkedService


def test_connect_initializes_connection_when_linked_service_is_provided() -> None:
    """
    It initializes the connection by calling linked service connect.
    """

    http = HttpClient(response=HttpResponseBytes(content=b""))
    linked_service = LinkedService(http=http)
    props = HttpDatasetTypedProperties(url="https://example.test/data")
    dataset = HttpDataset(linked_service=cast("Any", linked_service), typed_properties=props)
    dataset.connect()
    assert dataset.connection is http
    assert dataset.kind == ResourceKind.DATASET


def test_connect_raises_when_linked_service_is_missing() -> None:
    """
    It raises ConnectionError when connect is called without a linked service.
    """
    props = HttpDatasetTypedProperties(url="https://example.test/data")
    dataset = HttpDataset(linked_service=cast("Any", None), typed_properties=props)
    with pytest.raises(ConnectionError):
        dataset.connect()


def test_create_raises_when_connection_is_missing() -> None:
    """
    It raises ConnectionError when called without an initialized connection.
    """

    props = HttpDatasetTypedProperties(url="https://example.test/data")
    dataset = HttpDataset(linked_service=cast("Any", None), typed_properties=props)
    with pytest.raises(ConnectionError):
        dataset.create()


def test_read_raises_when_connection_is_missing() -> None:
    """
    It raises ConnectionError when read is called without an initialized connection.
    """

    props = HttpDatasetTypedProperties(url="https://example.test/data")
    dataset = HttpDataset(linked_service=cast("Any", None), typed_properties=props)
    with pytest.raises(ConnectionError):
        dataset.read()


def test_create_serializes_and_deserializes_when_content_is_present() -> None:
    """
    It serializes outgoing content and deserializes response content.
    """

    deserializer = DeserializerStub()
    http = HttpClient(response=HttpResponseBytes(content=b'{"ok": 1}'))
    linked_service = LinkedService(http=http)
    props = HttpDatasetTypedProperties(url="https://example.test/data", method="POST")
    dataset = HttpDataset(
        linked_service=cast("Any", linked_service),
        typed_properties=props,
        deserializer=cast("Any", deserializer),
    )
    dataset.connect()
    dataset.content = pd.DataFrame([{"x": 1}])
    dataset.create()
    assert deserializer.called_with == b'{"ok": 1}'
    assert isinstance(dataset.content, pd.DataFrame)
    assert http.last_request is not None
    assert http.last_request["method"] == "POST"
    assert http.last_request["url"] == "https://example.test/data"


def test_create_without_serializer_still_makes_request_and_deserializes() -> None:
    """
    It can run create when serializer is None and still deserialize response content.
    """

    deserializer = DeserializerStub()
    http = HttpClient(response=HttpResponseBytes(content=b'{"ok": 1}'))
    linked_service = LinkedService(http=http)
    props = HttpDatasetTypedProperties(url="https://example.test/data", method="POST", data=b"raw")
    dataset = HttpDataset(
        linked_service=cast("Any", linked_service),
        typed_properties=props,
        serializer=None,
        deserializer=cast("Any", deserializer),
    )
    dataset.connect()
    dataset.content = pd.DataFrame([{"x": 1}])
    dataset.create()
    assert http.last_request is not None
    assert http.last_request["data"] == b"raw"
    assert isinstance(dataset.content, pd.DataFrame)


def test_create_sets_empty_dataframe_when_response_has_no_content() -> None:
    """
    It sets content to an empty DataFrame when response content is empty.
    """

    http = HttpClient(response=HttpResponseBytes(content=b""))
    linked_service = LinkedService(http=http)
    props = HttpDatasetTypedProperties(url="https://example.test/data")
    dataset = HttpDataset(linked_service=cast("Any", linked_service), typed_properties=props)
    dataset.connect()
    dataset.create()
    assert isinstance(dataset.content, pd.DataFrame)
    assert dataset.content.empty is True


def test_read_sets_next_and_cursor_when_deserializer_indicates_more() -> None:
    """
    It populates next and cursor fields when deserializer reports pagination.
    """

    deserializer = DeserializerStub(next_value=True, cursor_value="c")
    http = HttpClient(response=HttpResponseBytes(content=b'{"ok": 1, "next": true}'))
    linked_service = LinkedService(http=http)
    props = HttpDatasetTypedProperties(url="https://example.test/data")
    dataset = HttpDataset(
        linked_service=cast("Any", linked_service),
        typed_properties=props,
        deserializer=cast("Any", deserializer),
    )
    dataset.connect()
    dataset.read()
    assert dataset.next is True
    assert dataset.cursor == "c"


def test_read_does_not_set_cursor_when_next_is_false() -> None:
    """
    It leaves cursor unset when deserializer reports no further page.
    """

    deserializer = DeserializerStub(next_value=False, cursor_value="c")
    http = HttpClient(response=HttpResponseBytes(content=b'{"ok": 1}'))
    linked_service = LinkedService(http=http)
    props = HttpDatasetTypedProperties(url="https://example.test/data")
    dataset = HttpDataset(
        linked_service=cast("Any", linked_service),
        typed_properties=props,
        deserializer=cast("Any", deserializer),
    )
    dataset.connect()
    dataset.read()
    assert dataset.next is False
    assert dataset.cursor is None


def test_read_sets_defaults_when_response_has_no_content() -> None:
    """
    It sets next to False, cursor to None, and content to empty DataFrame when no content exists.
    """

    http = HttpClient(response=HttpResponseBytes(content=b""))
    linked_service = LinkedService(http=http)
    props = HttpDatasetTypedProperties(url="https://example.test/data")
    dataset = HttpDataset(linked_service=cast("Any", linked_service), typed_properties=props)
    dataset.connect()
    dataset.read()
    assert dataset.next is False
    assert dataset.cursor is None
    assert isinstance(dataset.content, pd.DataFrame)
    assert dataset.content.empty is True


def test_read_wraps_resource_exception_into_read_error() -> None:
    """
    It wraps a provider ResourceException into ReadError and includes dataset type in details.
    """
    http = HttpClient(
        response=HttpResponseBytes(content=b""),
        error=ResourceException(message="boom", status_code=418, details={}),
    )
    linked_service = LinkedService(http=http)
    props = HttpDatasetTypedProperties(url="https://example.test/data")
    dataset = HttpDataset(linked_service=cast("Any", linked_service), typed_properties=props)
    dataset.connect()
    with pytest.raises(ReadError) as exc_info:
        dataset.read()
    assert exc_info.value.status_code == 418
    assert exc_info.value.details["type"] == ResourceKind.DATASET


def test_create_wraps_resource_exception_into_write_error() -> None:
    """
    It wraps a provider ResourceException into WriteError and includes dataset type in details.
    """
    http = HttpClient(
        response=HttpResponseBytes(content=b""),
        error=ResourceException(message="boom", status_code=418, details={}),
    )
    linked_service = LinkedService(http=http)
    props = HttpDatasetTypedProperties(url="https://example.test/data", method="POST")
    dataset = HttpDataset(linked_service=cast("Any", linked_service), typed_properties=props)
    dataset.connect()
    with pytest.raises(WriteError) as exc_info:
        dataset.create()
    assert exc_info.value.status_code == 418
    assert exc_info.value.details["type"] == ResourceKind.DATASET


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
    props = HttpDatasetTypedProperties(url="https://example.test/data")
    dataset = HttpDataset(linked_service=cast("Any", linked_service), typed_properties=props)
    dataset.connect()
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
    props = HttpDatasetTypedProperties(url="https://example.test/data", method="POST")
    dataset = HttpDataset(linked_service=cast("Any", linked_service), typed_properties=props)
    dataset.connect()
    with pytest.raises(type(exc)):
        dataset.create()


def test_dataset_unimplemented_methods_raise() -> None:
    """
    It raises NotImplementedError for delete/update/rename.
    """
    http = HttpClient(response=HttpResponseBytes(content=b""))
    linked_service = LinkedService(http=http)
    props = HttpDatasetTypedProperties(url="https://example.test/data")
    dataset = HttpDataset(linked_service=cast("Any", linked_service), typed_properties=props)
    dataset.connect()
    with pytest.raises(NotImplementedError):
        dataset.delete()
    with pytest.raises(NotImplementedError):
        dataset.update()
    with pytest.raises(NotImplementedError):
        dataset.rename()
