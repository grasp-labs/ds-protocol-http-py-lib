"""
**File:** ``provider.py``
**Region:** ``ds_protocol_http_py_lib/utils/http/provider``

HTTP Provider

This module implements a synchronous HTTP client with:
- requests.Session + urllib3.Retry (429/5xx, backoff, Retry-After)
- optional TokenBucket for simple RPS throttling
- context-managed lifetime
- tiny API: request/get/post/close

Example:
    >>> with Http() as client:
    ...     response = client.get("https://api.example.com/data")
    ...     data = response.json()
"""

import logging
import time
from dataclasses import dataclass
from typing import Any

import requests
from ds_common_logger_py_lib.mixin import LoggingMixin
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from ...utils.http.config import HttpConfig
from ...utils.http.token_bucket import TokenBucket


@dataclass(kw_only=True)
class Http(LoggingMixin):
    """
    Minimal synchronous HTTP client with:
      - requests.Session + urllib3.Retry (429/5xx, backoff, Retry-After)
      - optional TokenBucket for simple RPS throttling
      - context-managed lifetime
      - tiny API: request/get/post/close
    """

    log_level = logging.DEBUG

    def __init__(
        self,
        *,
        config: HttpConfig | None = None,
        bucket: TokenBucket | None = None,
        session: requests.Session | None = None,
    ) -> None:
        self._cfg = config or HttpConfig()
        self._bucket = bucket or TokenBucket()
        self._session = session or self._build_session()
        self.log.info(f"HTTP client initialized with timeout={self._cfg.timeout_seconds}s")

    def _build_session(self) -> requests.Session:
        """
        Build the session.
        Returns:
            requests.Session: The session.
        """
        session = requests.Session()
        headers = dict(self._cfg.headers or {})
        headers.setdefault("User-Agent", self._cfg.user_agent)
        session.headers.update(headers)

        retry = Retry(
            total=self._cfg.retry.total,
            backoff_factor=self._cfg.retry.backoff_factor,
            status_forcelist=self._cfg.retry.status_forcelist,
            allowed_methods=self._cfg.retry.allowed_methods,
            raise_on_status=self._cfg.retry.raise_on_status,
            respect_retry_after_header=self._cfg.retry.respect_retry_after_header,
        )
        self.log.debug(
            f"Retry config: total={retry.total}, "
            f"allowed_methods={retry.allowed_methods}, "
            f"status_forcelist={retry.status_forcelist}, "
            f"backoff_factor={retry.backoff_factor}"
        )
        adapter = HTTPAdapter(
            max_retries=retry,
            pool_maxsize=self._cfg.pool_maxsize,
            pool_connections=self._cfg.pool_connections,
        )
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        return session

    # ---- context ----
    @property
    def session(self) -> requests.Session:
        """
        Get the underlying requests session for direct use.
        Allows direct access to session properties like headers.

        Returns:
            requests.Session: The requests session.

        Example:
            >>> http = Http()
            >>> http.session.headers.update({"Authorization": "Bearer token"})
        """
        return self._session

    def __enter__(self) -> "Http":
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.close()

    def close(self) -> None:
        self._session.close()

    # ---- request ----

    def request(self, method: str, url: str, **kwargs: Any) -> requests.Response:
        """
        Send an HTTP request with rate limiting, retry logic, and comprehensive logging.

        Args:
            method: HTTP method (GET, POST, PUT, DELETE, etc.).
            url: Target URL for the request.
            **kwargs: Additional keyword arguments passed to requests (timeout, headers, data, etc.).

        Returns:
            requests.Response: The HTTP response object.

        Raises:
            requests.HTTPError: If the response status code indicates an error.
            requests.RequestException: For other request-related errors.

        Example:
            >>> with Http() as client:
            ...     response = client.request('GET', 'https://api.example.com/data', timeout=30)
            ...     data = response.json()
        """
        start_time = time.time()
        request_id = f"{method}_{int(start_time * 1000)}"

        self.log.debug(
            f"[{request_id}] Initiating {method} request to {url} with timeout={kwargs.get('timeout', self._cfg.timeout_seconds)}s"
        )
        kwargs.setdefault("timeout", self._cfg.timeout_seconds)
        self.log.debug(f"[{request_id}] Acquiring rate limit token (available: {self._bucket.available()})")
        self._bucket.acquire()
        self.log.debug(f"[{request_id}] Rate limit token acquired (remaining: {self._bucket.tokens})")

        response = self._session.request(method, url, **kwargs)

        duration = time.time() - start_time
        self.log.debug(
            f"[{request_id}] Request completed in {duration:.3f}s "
            f"with status {response.status_code} "
            f"(content-length: {response.headers.get('content-length', 'unknown')})"
        )

        response.raise_for_status()
        return response

    # ---- convenience methods ----

    def get(self, url: str, **kwargs: Any) -> requests.Response:
        """
        Send a GET request with enhanced logging.

        Args:
            url: Target URL for the GET request.
            **kwargs: Additional keyword arguments passed to requests.

        Returns:
            requests.Response: The HTTP response object.

        Example:
            >>> with Http() as client:
            ...     response = client.get("https://api.example.com/data")
        """
        self.log.debug(f"GET request to {url}")
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs: Any) -> requests.Response:
        """
        Send a POST request with enhanced logging.

        Args:
            url: Target URL for the POST request.
            **kwargs: Additional keyword arguments passed to requests.

        Returns:
            requests.Response: The HTTP response object.

        Example:
            >>> with Http() as client:
            ...     response = client.post("https://api.example.com/data", json={"key": "value"})
        """
        self.log.debug(f"POST request to {url}")
        return self.request("POST", url, **kwargs)

    def put(self, url: str, **kwargs: Any) -> requests.Response:
        """
        Send a PUT request with enhanced logging.

        Args:
            url: Target URL for the PUT request.
            **kwargs: Additional keyword arguments passed to requests.

        Returns:
            requests.Response: The HTTP response object.

        Example:
            >>> with Http() as client:
            ...     response = client.put("https://api.example.com/data/1", json={"key": "value"})
        """
        self.log.debug(f"PUT request to {url}")
        return self.request("PUT", url, **kwargs)

    def delete(self, url: str, **kwargs: Any) -> requests.Response:
        """
        Send a DELETE request with enhanced logging.

        Args:
            url: Target URL for the DELETE request.
            **kwargs: Additional keyword arguments passed to requests.

        Returns:
            requests.Response: The HTTP response object.

        Example:
            >>> with Http() as client:
            ...     response = client.delete("https://api.example.com/data/1")
        """
        self.log.debug(f"DELETE request to {url}")
        return self.request("DELETE", url, **kwargs)
