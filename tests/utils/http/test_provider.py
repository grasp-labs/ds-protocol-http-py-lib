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

from ds_protocol_http_py_lib.utils.http.config import HttpConfig
from ds_protocol_http_py_lib.utils.http.provider import Http
from tests.mocks import ProviderResponse, ProviderSession, TrackingBucket


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
    session = ProviderSession(response=ProviderResponse(status_code=200, headers={}))
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


def test_http_request_raises_http_error_on_failure_status() -> None:
    """
    It raises requests.HTTPError when the response indicates an error.
    """

    url = "https://example.test/bad"
    err = requests.HTTPError("bad")
    session = ProviderSession(response=ProviderResponse(status_code=400, headers={}, raise_error=err))
    http = Http(
        config=HttpConfig(timeout_seconds=1),
        bucket=cast("Any", TrackingBucket()),
        session=cast("requests.Session", session),
    )
    with pytest.raises(requests.HTTPError):
        http.request("GET", url)
    assert session.last is not None
    assert session.last[2]["timeout"] == 1


def test_http_request_preserves_explicit_timeout() -> None:
    """
    It forwards an explicit timeout to the underlying session request.
    """

    url = "https://example.test/ok"
    session = ProviderSession(response=ProviderResponse(status_code=200, headers={}))
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

    session = ProviderSession(response=ProviderResponse(status_code=200, headers={}))
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

    session = ProviderSession(response=ProviderResponse(status_code=200, headers={}))
    with Http(
        config=HttpConfig(timeout_seconds=1),
        bucket=cast("Any", TrackingBucket()),
        session=cast("requests.Session", session),
    ) as http:
        http.get("https://example.test/ok")
    assert session.closed is True
