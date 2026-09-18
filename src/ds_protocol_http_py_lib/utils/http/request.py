"""
**File:** ``request.py``
**Region:** ``ds_protocol_http_py_lib/utils/http/request``

Outbound HTTP request copy and param injection.

Used by dataset pagination and incremental watermark rules so they never
mutate dataset settings in place.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from enum import StrEnum
from typing import Any


class InjectLocation(StrEnum):
    """Where a value is written on the request."""

    QUERY = "query"
    HEADER = "header"
    BODY = "body"


@dataclass
class RequestSnapshot:
    """Isolated copy of outbound request fields."""

    url: str
    method: Any
    data: Any = None
    json: dict[str, Any] | None = None
    params: dict[str, Any] | None = None
    headers: dict[str, Any] | None = None
    files: Any = None

    def clone(self) -> RequestSnapshot:
        """Deep-copy mutable containers."""
        return RequestSnapshot(
            url=self.url,
            method=self.method,
            data=deepcopy(self.data),
            json=deepcopy(self.json),
            params=deepcopy(self.params),
            headers=deepcopy(self.headers),
            files=self.files,
        )

    def inject(self, name: str, value: Any, location: InjectLocation) -> RequestSnapshot:
        """Return a clone with ``value`` written at ``location`` under ``name``."""
        out = self.clone()
        if location is InjectLocation.QUERY:
            params = dict(out.params or {})
            params[name] = value
            out.params = params
            return out
        if location is InjectLocation.HEADER:
            headers = dict(out.headers or {})
            headers[name] = value
            out.headers = headers
            return out
        if location is InjectLocation.BODY:
            body = dict(out.json or {})
            body[name] = value
            out.json = body
            return out
        raise ValueError(f"Unsupported inject location: {location}")

    def to_request_kwargs(self) -> dict[str, Any]:
        """Keyword arguments for ``connection.request``."""
        return {
            "method": self.method,
            "url": self.url,
            "data": self.data,
            "json": self.json,
            "params": self.params,
            "headers": self.headers,
            "files": self.files,
        }


def get_header(headers: Any, name: str) -> str | None:
    """Case-insensitive header lookup; empty values become ``None``."""
    target = name.lower()
    for key, value in headers.items():
        if str(key).lower() == target:
            if value is None or value == "":
                return None
            return value if isinstance(value, str) else str(value)
    return None
