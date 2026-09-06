"""
**File:** ``inject.py``
**Region:** ``ds_protocol_http_py_lib/dataset/pagination/inject``

Request snapshots and value injection for pagination and incremental reads.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from .enums import InjectLocation

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    from ...models import Files


@dataclass
class RequestSnapshot:
    """
    Mutable copy of outbound HTTP request fields.

    Used so pagination / watermark injection never mutates dataset settings.
    """

    url: str
    """Resolved request URL."""

    method: Any
    """HTTP method."""

    data: Any = None
    """Raw body payload."""

    json: dict[str, Any] | None = None
    """JSON body object."""

    params: dict[str, Any] | None = None
    """Query parameters."""

    headers: dict[str, Any] | None = None
    """Request headers."""

    files: Any = None
    """``requests``-compatible multipart files mapping."""

    def clone(self) -> RequestSnapshot:
        """Deep-copy mutable containers so page injections do not leak."""
        return RequestSnapshot(
            url=self.url,
            method=self.method,
            data=deepcopy(self.data),
            json=deepcopy(self.json),
            params=deepcopy(self.params),
            headers=deepcopy(self.headers),
            files=self.files,
        )

    def to_request_kwargs(self) -> dict[str, Any]:
        """Keyword arguments accepted by ``connection.request``."""
        return {
            "method": self.method,
            "url": self.url,
            "data": self.data,
            "json": self.json,
            "params": self.params,
            "headers": self.headers,
            "files": self.files,
        }


@dataclass
class PageState:
    """Strategy-owned traversal state for one paginated read."""

    values: dict[str, Any] = field(default_factory=dict)
    """Opaque strategy values (offset, page, cursor, …)."""

    page_index: int = 0
    """Zero-based count of pages fetched so far."""


def snapshot_from_settings(
    *,
    url: str,
    method: Any,
    data: Any = None,
    json_body: dict[str, Any] | None = None,
    params: dict[str, Any] | None = None,
    headers: dict[str, Any] | None = None,
    files: Sequence[Files] | None = None,
    map_files: Callable[[Sequence[Files] | None], Any],
) -> RequestSnapshot:
    """
    Build a request snapshot from flat HTTP dataset settings.

    Mutable containers are deep-copied so later injection is isolated.
    """
    return RequestSnapshot(
        url=url,
        method=method,
        data=deepcopy(data),
        json=deepcopy(json_body),
        params=deepcopy(params),
        headers=deepcopy(headers),
        files=map_files(files),
    )


def inject_value(
    request: RequestSnapshot,
    *,
    name: str,
    value: Any,
    location: InjectLocation,
) -> RequestSnapshot:
    """
    Inject ``value`` into a cloned request at the configured location.

    ``InjectLocation.BODY`` writes into the JSON body (``request.json``).
    """
    out = request.clone()
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
