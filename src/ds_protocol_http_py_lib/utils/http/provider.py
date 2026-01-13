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
from ds_resource_plugin_py_lib.common.resource.errors import ResourceException
from ds_resource_plugin_py_lib.common.resource.linked_service.errors import (
    AuthenticationError,
    AuthorizationError,
    ConnectionError,
)
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

    def _response_info(self, response: requests.Response) -> dict[str, Any]:
        """
        Get information about a response.
        Extracts the status code, URL, method, reason, content, and body from the response.

        Args:
            response: The HTTP response object to extract info from.

        Returns:
            dict[str, Any]: Dictionary containing the response information.
        """
        info = {
            "status_code": response.status_code,
            "url": response.url,
            "method": response.request.method,
            "reason": response.reason,
        }
        try:
            req = response.request

            body = getattr(req, "body", None)
            if body is not None:
                if isinstance(body, bytes):
                    body_preview = body[:500].decode("utf-8", errors="replace")
                elif isinstance(body, str):
                    body_preview = body[:500]
                else:
                    body_preview = str(body)[:500]
            else:
                body_preview = None

            info["content"] = response.content[:500] if response.content is not None else None
            info["body"] = body_preview
        except Exception as exc:
            self.log.warning(f"Failed to get full response info: {exc}")

        return info

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

        response_info = None
        try:
            response = self._session.request(method, url, **kwargs)
            duration = time.time() - start_time
            response_info = self._response_info(response)
            self.log.debug(
                f"[{request_id}] Request completed in {duration:.3f}s "
                f"with status {response.status_code} "
                f"and response: {response_info}"
            )
            response.raise_for_status()
        except requests.HTTPError as exc:
            self.log.exception(f"HTTP error: {exc} with response: {response_info}")
            if exc.response.status_code == 401:
                raise AuthenticationError(
                    message=f"Authentication error: {exc}",
                    details={
                        "response_body": exc.response.text,
                        "reason": exc.response.reason,
                        "url": exc.response.url,
                        "method": exc.response.request.method,
                    },
                ) from exc
            elif exc.response.status_code == 403:
                raise AuthorizationError(
                    message=f"Authorization error: {exc}",
                    details={
                        "response_body": exc.response.text,
                        "reason": exc.response.reason,
                        "url": exc.response.url,
                        "method": exc.response.request.method,
                    },
                ) from exc
            raise ResourceException(
                message=f"HTTP error: {exc}",
                status_code=exc.response.status_code,
                details={
                    "response_body": exc.response.text,
                    "reason": exc.response.reason,
                    "url": exc.response.url,
                    "method": exc.response.request.method,
                },
            ) from exc
        except requests.exceptions.ConnectionError as exc:
            self.log.exception(f"Connection error: {exc} with response: {response_info}")
            raise ConnectionError(
                message=f"Connection error: {exc}",
                details={
                    "url": url,
                    "method": method,
                    "error_type": type(exc).__name__,
                    "error_message": str(exc),
                },
            ) from exc
        except Exception as exc:
            self.log.exception(f"HTTP request error: {exc} with response: {response_info}")
            raise ResourceException(
                message=f"HTTP error: {exc}",
                details={
                    "url": url,
                    "method": method,
                    "error_type": type(exc).__name__,
                    "error_message": str(exc),
                },
            ) from exc

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
