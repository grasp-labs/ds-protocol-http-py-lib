"""
**File:** ``config.py``
**Region:** ``ds_protocol_http_py_lib/utils/http/config``

Configuration for the HTTP client.

Example:
    >>> config = HttpConfig(timeout_seconds=10, user_agent="MyUA/1.0")
    >>> retry = RetryConfig(total=3, backoff_factor=0.2, status_forcelist=(429, 500, 502, 503, 504))
    >>> http = Http(config=config, retry=retry)
    >>> response = http.get("https://api.example.com/data")
    >>> data = response.json()
"""

from collections.abc import Mapping
from dataclasses import dataclass, field

# ---------- Config ----------


@dataclass(frozen=True, kw_only=True)
class RetryConfig:
    """
    Retry policy (urllib3 Retry via requests).

    - total: max attempts (includes first request)
    - backoff_factor: sleep = factor * (2 ** (retry_num - 1))
    - status_forcelist: statuses that trigger retry
    - allowed_methods: methods eligible for retry
    - respect_retry_after_header: honor Retry-After on 429/503
    """

    total: int = 3
    backoff_factor: float = 0.2
    status_forcelist: tuple[int, ...] = (429, 500, 502, 503, 504)
    allowed_methods: tuple[str, ...] = ("GET", "POST", "PUT", "DELETE", "PATCH")
    raise_on_status: bool = False
    respect_retry_after_header: bool = True


@dataclass(frozen=True, kw_only=True)
class HttpConfig:
    """
    Configuration for the HTTP client.
    - headers: applied to all requests (overridable per call)
    - timeout_seconds: connect+read timeout seconds (or (connect, read) per call)
    - user_agent: user agent for all requests
    - pool_maxsize: maximum number of connections in the pool
    - pool_connections: maximum number of connections in the pool
    - raise_for_status: raise for status for all requests
    - retry: RetryConfig
    """

    # Headers configuration
    headers: Mapping[str, str] = field(default_factory=dict)

    # Request configuration
    timeout_seconds: int | float = 10
    user_agent: str = field(default="Http/1.0")
    pool_maxsize: int = field(default=32)
    pool_connections: int = field(default=10)

    # Retry configuration
    retry: RetryConfig = field(default_factory=RetryConfig)
