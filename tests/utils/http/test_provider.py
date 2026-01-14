"""
**File:** ``test_provider.py``
**Region:** ``tests/utils/http/test_provider``

HTTP provider tests.

Covers:
- Session construction defaults (User-Agent and adapter mounts).
- request() success/error behavior and rate limiter acquisition.
- Convenience methods (get/post/put/delete) delegation to request().
- Context manager lifecycle closing the underlying session.
"""

from __future__ import annotations

from typing import Any, cast

import pytest
import requests
from ds_resource_plugin_py_lib.common.resource.errors import ResourceException
from ds_resource_plugin_py_lib.common.resource.linked_service.errors import (
    AuthenticationError,
    AuthorizationError,
    ConnectionError,
)

from ds_protocol_http_py_lib.utils.http.config import HttpConfig
from ds_protocol_http_py_lib.utils.http.provider import Http
from tests.mocks import ProviderSession, TrackingBucket, build_response


def test_http_build_session_sets_user_agent_by_default() -> None:
    """
    It sets a default User-Agent header when one is not provided.
    """

    cfg = HttpConfig(headers={}, user_agent="MyUA/1.0")
    http = Http(config=cfg)
    assert http.session.headers["User-Agent"] == "MyUA/1.0"
    assert "http://" in http.session.adapters
    assert "https://" in http.session.adapters


def test_http_request_acquires_bucket_token_and_returns_response() -> None:
    """
    It acquires a rate limit token and returns the requests response on success.
    """

    url = "https://example.test/ok"
    bucket = TrackingBucket()
    session = ProviderSession(response=build_response(status_code=200, url=url, method="GET"))
    http = Http(
        config=HttpConfig(timeout_seconds=1),
        bucket=cast("Any", bucket),
        session=cast("requests.Session", session),
    )
    response = http.request("GET", url)
    assert bucket.called == 1
    assert response.status_code == 200
    assert session.last is not None
    assert session.last[2]["timeout"] == 1


def test_http_request_raises_authentication_error_on_401() -> None:
    """
    It translates a 401 HTTPError into AuthenticationError.
    """

    url = "https://example.test/bad"
    response = build_response(status_code=401, body="nope", url=url, method="GET", reason="Unauthorized")
    response.raise_for_status = lambda: (_ for _ in ()).throw(  # type: ignore[method-assign]
        requests.HTTPError("boom", response=response)
    )
    session = ProviderSession(response=response)
    http = Http(
        config=HttpConfig(timeout_seconds=1),
        bucket=cast("Any", TrackingBucket()),
        session=cast("requests.Session", session),
    )
    with pytest.raises(AuthenticationError) as exc_info:
        http.request("GET", url)
    assert exc_info.value.details["url"] == url
    assert exc_info.value.details["method"] == "GET"
    assert "nope" in str(exc_info.value.details["response_body"])
    assert session.last is not None
    assert session.last[2]["timeout"] == 1


def test_http_request_raises_authorization_error_on_403() -> None:
    """
    It translates a 403 HTTPError into AuthorizationError.
    """
    url = "https://example.test/forbidden"
    response = build_response(status_code=403, body="nope", url=url, method="GET", reason="Forbidden")
    response.raise_for_status = lambda: (_ for _ in ()).throw(  # type: ignore[method-assign]
        requests.HTTPError("boom", response=response)
    )
    session = ProviderSession(response=response)
    http = Http(
        config=HttpConfig(timeout_seconds=1),
        bucket=cast("Any", TrackingBucket()),
        session=cast("requests.Session", session),
    )
    with pytest.raises(AuthorizationError):
        http.request("GET", url)


def test_http_request_raises_resource_exception_on_other_http_error() -> None:
    """
    It translates other HTTP errors into ResourceException with status_code.
    """
    url = "https://example.test/bad"
    response = build_response(status_code=400, body="bad", url=url, method="GET", reason="Bad Request")
    response.raise_for_status = lambda: (_ for _ in ()).throw(  # type: ignore[method-assign]
        requests.HTTPError("boom", response=response)
    )
    session = ProviderSession(response=response)
    http = Http(
        config=HttpConfig(timeout_seconds=1),
        bucket=cast("Any", TrackingBucket()),
        session=cast("requests.Session", session),
    )
    with pytest.raises(ResourceException) as exc_info:
        http.request("GET", url)
    assert exc_info.value.status_code == 400


def test_http_request_raises_connection_error_on_requests_connection_error() -> None:
    """
    It translates requests.exceptions.ConnectionError into ConnectionError.
    """
    url = "https://example.test/down"
    session = ProviderSession(
        response=build_response(status_code=200, url=url, method="GET"),
        request_error=requests.exceptions.ConnectionError("down"),
    )
    http = Http(
        config=HttpConfig(timeout_seconds=1),
        bucket=cast("Any", TrackingBucket()),
        session=cast("requests.Session", session),
    )
    with pytest.raises(ConnectionError) as exc_info:
        http.request("GET", url)
    assert exc_info.value.details["url"] == url
    assert exc_info.value.details["method"] == "GET"


def test_http_request_raises_resource_exception_on_unexpected_exception() -> None:
    """
    It translates unexpected exceptions into ResourceException with diagnostic details.
    """
    url = "https://example.test/oops"
    session = ProviderSession(
        response=build_response(status_code=200, url=url, method="GET"),
        request_error=RuntimeError("boom"),
    )
    http = Http(
        config=HttpConfig(timeout_seconds=1),
        bucket=cast("Any", TrackingBucket()),
        session=cast("requests.Session", session),
    )
    with pytest.raises(ResourceException) as exc_info:
        http.request("GET", url)
    assert exc_info.value.details["url"] == url
    assert exc_info.value.details["method"] == "GET"
    assert exc_info.value.details["error_type"] == "RuntimeError"


@pytest.mark.parametrize(
    "request_body",
    [b"bytes-body", "string-body", {"x": 1}],
)
def test_response_info_handles_various_request_body_types(request_body: Any) -> None:
    """
    _response_info should safely extract body previews for bytes/str/other types.
    """
    http = Http(config=HttpConfig(timeout_seconds=1), bucket=cast("Any", TrackingBucket()))
    resp = build_response(
        status_code=200,
        body=b"hello",
        url="https://example.test/info",
        method="POST",
        request_body=request_body,
    )
    info = http._response_info(resp)
    assert info["status_code"] == 200
    assert info["url"] == "https://example.test/info"
    assert info["method"] == "POST"
    assert "body" in info


def test_http_request_preserves_explicit_timeout() -> None:
    """
    It forwards an explicit timeout to the underlying session request.
    """

    url = "https://example.test/ok"
    session = ProviderSession(response=build_response(status_code=200, url=url, method="GET"))
    http = Http(
        config=HttpConfig(timeout_seconds=1),
        bucket=cast("Any", TrackingBucket()),
        session=cast("requests.Session", session),
    )
    http.request("GET", url, timeout=5)
    assert session.last is not None
    assert session.last[2]["timeout"] == 5


def test_http_convenience_methods_delegate_to_request() -> None:
    """
    It delegates get/post/put/delete to request with the correct method.
    """

    session = ProviderSession(response=build_response(status_code=200, url="https://example.test/", method="GET"))
    http = Http(
        config=HttpConfig(timeout_seconds=1),
        bucket=cast("Any", TrackingBucket()),
        session=cast("requests.Session", session),
    )
    http.get("https://example.test/get")
    assert session.last is not None
    assert session.last[0] == "GET"

    http.post("https://example.test/post")
    assert session.last[0] == "POST"

    http.put("https://example.test/put")
    assert session.last[0] == "PUT"

    http.delete("https://example.test/delete")
    assert session.last[0] == "DELETE"


def test_http_context_manager_closes_session() -> None:
    """
    It closes the underlying session when exiting context.
    """

    session = ProviderSession(response=build_response(status_code=200, url="https://example.test/ok", method="GET"))
    with Http(
        config=HttpConfig(timeout_seconds=1),
        bucket=cast("Any", TrackingBucket()),
        session=cast("requests.Session", session),
    ) as http:
        http.get("https://example.test/ok")
    assert session.closed is True
