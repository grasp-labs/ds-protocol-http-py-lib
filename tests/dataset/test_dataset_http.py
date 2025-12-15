"""
HttpDataset behavior tests.

Covers:
- Connection initialization via linked service in __post_init__.
- create/read request execution and argument propagation.
- Serializer/deserializer interactions and empty-response handling.
- Pagination state updates (next/cursor) driven by the deserializer.
"""

from __future__ import annotations

from typing import Any, cast

import pandas as pd
import pytest
from ds_resource_plugin_py_lib.common.resource.linked_service.errors import ConnectionException

from ds_protocol_http_py_lib.dataset.http import HttpDataset, HttpDatasetTypedProperties
from ds_protocol_http_py_lib.enums import ResourceKind
from tests.mocks import DeserializerStub, HttpClient, HttpResponseBytes, LinkedService


def test_post_init_connects_when_linked_service_is_provided() -> None:
    """
    It initializes the connection by calling linked service connect.
    """

    http = HttpClient(response=HttpResponseBytes(content=b""))
    linked_service = LinkedService(http=http)
    props = HttpDatasetTypedProperties(url="https://example.test/data")
    dataset = HttpDataset(linked_service=cast("Any", linked_service), typed_properties=props)
    assert dataset.connection is http
    assert dataset.kind == ResourceKind.DATASET


def test_create_raises_when_connection_is_missing() -> None:
    """
    It raises ConnectionException when called without an initialized connection.
    """

    props = HttpDatasetTypedProperties(url="https://example.test/data")
    dataset = HttpDataset(linked_service=cast("Any", None), typed_properties=props)
    with pytest.raises(ConnectionException):
        dataset.create()


def test_read_raises_when_connection_is_missing() -> None:
    """
    It raises ConnectionException when read is called without an initialized connection.
    """

    props = HttpDatasetTypedProperties(url="https://example.test/data")
    dataset = HttpDataset(linked_service=cast("Any", None), typed_properties=props)
    with pytest.raises(ConnectionException):
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
    dataset.read()
    assert dataset.next is False
    assert dataset.cursor is None
    assert isinstance(dataset.content, pd.DataFrame)
    assert dataset.content.empty is True
