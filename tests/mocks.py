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

from dataclasses import dataclass
from typing import Any

import pandas as pd
from requests import HTTPError, Response


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


@dataclass(slots=True)
class ProviderResponse:
    """
    Minimal response used by provider Http unit tests.
    """

    status_code: int
    headers: dict[str, str]
    raise_error: Exception | None = None

    def raise_for_status(self) -> None:
        if self.raise_error is not None:
            raise self.raise_error


@dataclass(slots=True)
class ProviderSession:
    """
    Minimal requests.Session replacement for provider Http tests.
    """

    response: ProviderResponse
    last: tuple[str, str, dict[str, Any]] | None = None
    closed: bool = False
    headers: dict[str, str] | None = None

    def __post_init__(self) -> None:
        if self.headers is None:
            self.headers = {}

    def request(self, method: str, url: str, **kwargs: Any) -> ProviderResponse:
        self.last = (method, url, dict(kwargs))
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

    def request(self, **kwargs: Any) -> HttpResponseBytes:
        self.last_request = dict(kwargs)
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
class JsonResponse:
    """
    Minimal response with .json() for linked service tests.
    """

    json_data: Any

    def json(self) -> Any:
        return self.json_data


@dataclass(slots=True)
class LinkedServiceHttp:
    """
    Minimal Http-like object used by HttpLinkedService tests.
    """

    session: Any
    post_response: Any | None = None
    post_error: Exception | None = None
    get_error: Exception | None = None

    def post(self, url: str, **kwargs: Any) -> Any:
        if self.post_error is not None:
            raise self.post_error
        return self.post_response

    def get(self, url: str, **kwargs: Any) -> Any:
        if self.get_error is not None:
            raise self.get_error
        return object()


def http_error(status_code: int, body: str) -> HTTPError:
    """
    Create a requests.HTTPError with a populated response.
    """

    resp = Response()
    resp.status_code = status_code
    resp._content = body.encode("utf-8")
    return HTTPError("boom", response=resp)
