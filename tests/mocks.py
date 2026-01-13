"""
**File:** ``mocks.py``
**Region:** ``tests/mocks``

Centralized test doubles used across unit tests.

Covers:
- Provider-layer fakes (session/response, token bucket) for Http provider tests.
- Dataset-layer fakes (linked service, client, serializer/deserializer) for HttpDataset tests.
- Linked-service-layer fakes (Http-like client, JSON response, HTTPError factory) for auth/connection tests.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

import pandas as pd
from requests import HTTPError, Request, Response


@dataclass(slots=True)
class TrackingBucket:
    """
    Minimal token bucket that tracks acquire calls.
    """

    called: int = 0
    tokens: float = 1.0

    def acquire(self) -> None:
        self.called += 1

    def available(self) -> float:
        # Mirror TokenBucket.available() API for provider logging without mutating state.
        return self.tokens


def build_response(
    *,
    status_code: int = 200,
    body: str | bytes = b"",
    url: str = "https://example.test/",
    method: str = "GET",
    reason: str = "OK",
    headers: dict[str, str] | None = None,
    request_body: Any | None = None,
) -> Response:
    """
    Build a realistic requests.Response (incl. .request.method and .text).

    This keeps tests close to real requests behavior since production code
    relies on Response attributes like: url, reason, request.method, text/content.
    """
    resp = Response()
    resp.status_code = int(status_code)
    resp.url = url
    resp.reason = reason
    # requests.Response.headers is a CaseInsensitiveDict, but accepting a plain dict is fine at runtime.
    resp.headers = dict(headers or {})  # type: ignore[assignment]
    resp._content = body.encode("utf-8") if isinstance(body, str) else body

    # Attach a PreparedRequest so production code can access response.request.method/body.
    req = Request(method=method, url=url, data=request_body).prepare()
    resp.request = req
    return resp


def json_response(
    payload: Any,
    *,
    status_code: int = 200,
    url: str = "https://example.test/token",
    method: str = "POST",
    reason: str = "OK",
    headers: dict[str, str] | None = None,
) -> Response:
    """
    Convenience builder for JSON responses.
    """
    hdrs = {"Content-Type": "application/json", **dict(headers or {})}
    return build_response(
        status_code=status_code,
        body=json.dumps(payload),
        url=url,
        method=method,
        reason=reason,
        headers=hdrs,
    )


@dataclass(slots=True)
class ProviderSession:
    """
    Minimal requests.Session replacement for provider Http tests.
    """

    response: Response
    request_error: Exception | None = None
    last: tuple[str, str, dict[str, Any]] | None = None
    closed: bool = False
    headers: dict[str, str] | None = None

    def __post_init__(self) -> None:
        if self.headers is None:
            self.headers = {}

    def request(self, method: str, url: str, **kwargs: Any) -> Response:
        self.last = (method, url, dict(kwargs))
        if self.request_error is not None:
            raise self.request_error
        # Make sure response fields match the call site (url/method/body).
        self.response.url = url
        self.response.request = Request(
            method=method,
            url=url,
            data=kwargs.get("data"),
        ).prepare()
        return self.response

    def close(self) -> None:
        self.closed = True


@dataclass(slots=True)
class HttpResponseBytes:
    """
    Minimal response object for HttpDataset tests.
    """

    content: bytes


@dataclass(slots=True)
class HttpClient:
    """
    Minimal client for HttpDataset tests.
    """

    response: HttpResponseBytes
    last_request: dict[str, Any] | None = None
    error: Exception | None = None

    def request(self, **kwargs: Any) -> HttpResponseBytes:
        self.last_request = dict(kwargs)
        if self.error is not None:
            raise self.error
        return self.response


@dataclass(slots=True)
class LinkedService:
    """
    Minimal linked service for HttpDataset tests.
    """

    http: HttpClient

    def connect(self) -> HttpClient:
        return self.http


class SerializerSpy:
    """
    Serializer spy used by HttpDataset tests.
    """

    def __init__(self) -> None:
        self.called_with: Any | None = None

    def __call__(self, value: Any) -> Any:
        self.called_with = value
        return b"serialized"


class DeserializerStub:
    """
    Deserializer stub used by HttpDataset tests.
    """

    def __init__(self, *, next_value: bool = False, cursor_value: str | None = None) -> None:
        self.next_value = next_value
        self.cursor_value = cursor_value
        self.called_with: bytes | None = None

    def __call__(self, payload: bytes) -> pd.DataFrame:
        self.called_with = payload
        return pd.DataFrame([{"ok": 1}])

    def get_next(self, payload: bytes) -> bool:
        return self.next_value

    def get_end_cursor(self, payload: bytes) -> str | None:
        return self.cursor_value


@dataclass(slots=True)
class LinkedServiceHttp:
    """
    Minimal Http-like object used by HttpLinkedService tests.
    """

    session: Any
    post_response: Any | None = None
    post_error: Exception | None = None
    get_error: Exception | None = None
    get_response: Any | None = None

    def post(self, url: str, **kwargs: Any) -> Any:
        if self.post_error is not None:
            raise self.post_error
        return self.post_response

    def get(self, url: str, **kwargs: Any) -> Any:
        if self.get_error is not None:
            raise self.get_error
        return self.get_response if self.get_response is not None else object()


def http_error(
    status_code: int,
    body: str,
    *,
    url: str = "https://example.test/token",
    method: str = "POST",
    reason: str = "Error",
) -> HTTPError:
    """
    Create a requests.HTTPError with a populated response.
    """

    resp = build_response(
        status_code=status_code,
        body=body,
        url=url,
        method=method,
        reason=reason,
    )
    return HTTPError("boom", response=resp)
