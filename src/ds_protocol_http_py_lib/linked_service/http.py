"""
**File:** ``http.py``
**Region:** ``ds_protocol_http_py_lib/linked_service/http``

HTTP Linked Service

This module implements a linked service for HTTP APIs.

Example:
    >>> linked_service = HttpLinkedService(
    ...     typed_properties=HttpLinkedServiceTypedProperties(
    ...         host="https://api.example.com",
    ...         auth_type="OAuth2",
    ...     ),
    ... )
    >>> linked_service.connect()
"""

import base64
from dataclasses import dataclass, field
from typing import Generic, Literal, TypeVar

from ds_resource_plugin_py_lib.common.resource.linked_service import (
    LinkedService,
    LinkedServiceTypedProperties,
)
from ds_resource_plugin_py_lib.common.resource.linked_service.errors import (
    AuthenticationError,
)
from requests import HTTPError

from .. import PACKAGE_NAME, __version__
from ..enums import ResourceKind
from ..utils import find_keys_in_json
from ..utils.http.config import HttpConfig, RetryConfig
from ..utils.http.provider import Http
from ..utils.http.token_bucket import TokenBucket


@dataclass(kw_only=True)
class HttpLinkedServiceTypedProperties(LinkedServiceTypedProperties):
    """
    The object containing the HTTP linked service properties.
    """

    host: str
    auth_type: Literal[
        "OAuth2",
        "Basic",
        "APIKey",
        "Bearer",
        "NoAuth",
        "Custom",
    ]
    schema: str = "https"
    port: int | None = None
    api_key_name: str | None = None
    api_key_value: str | None = None
    username_key_name: str | None = "email"
    username_key_value: str | None = None
    password_key_name: str | None = "password"
    password_key_value: str | None = None
    client_id: str | None = None
    client_secret: str | None = None
    token_endpoint: str | None = None
    scope: str | None = None
    headers: dict[str, str] | None = None
    data: dict[str, str] | None = None


HttpLinkedServiceTypedPropertiesType = TypeVar(
    "HttpLinkedServiceTypedPropertiesType",
    bound=HttpLinkedServiceTypedProperties,
)


@dataclass(kw_only=True)
class HttpLinkedService(
    LinkedService[HttpLinkedServiceTypedPropertiesType],
    Generic[HttpLinkedServiceTypedPropertiesType],
):
    """
    The class is used to connect with HTTP API.
    """

    typed_properties: HttpLinkedServiceTypedPropertiesType
    _http: Http | None = field(default=None, init=False)
    _auth_configured: bool = field(default=False, init=False)

    def __post_init__(self) -> None:
        self.base_uri = (
            self.typed_properties.host
            if self.typed_properties.host and "://" in self.typed_properties.host
            else f"{self.typed_properties.schema}://{self.typed_properties.host}"
        )

        if self.typed_properties.port:
            self.base_uri = f"{self.typed_properties.host}:{self.typed_properties.port}"

        self._http = self._init_http()

    @property
    def kind(self) -> ResourceKind:
        """
        Get the kind of the linked service.
        Returns:
            ResourceKind
        """
        return ResourceKind.LINKED_SERVICE

    def _init_http(self) -> Http:
        """
        Initialize the Http client instance with HttpConfig and TokenBucket.

        Creates an Http instance with:
        - HttpConfig using headers from the linked service properties
        - TokenBucket with rate limiting (10 requests per second, capacity of 20)

        Subclasses can override this method to customize the entire Http initialization,
        including custom HttpConfig, TokenBucket, or other Http parameters.

        Returns:
            Http: The initialized Http client instance.
        """
        retry_config = RetryConfig(
            total=3,
            backoff_factor=0.2,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=("GET", "POST", "PUT", "DELETE", "PATCH"),
            raise_on_status=False,
            respect_retry_after_header=True,
        )
        config = HttpConfig(
            headers=dict(self.typed_properties.headers or {}),
            timeout_seconds=60,
            user_agent=f"{PACKAGE_NAME}/{__version__}",
            retry=retry_config,
        )
        token_bucket = TokenBucket(rps=10, capacity=20)
        return Http(config=config, bucket=token_bucket)

    def _fetch_user_token(self, http: Http) -> str:
        """
        Fetch a user token from the token endpoint using the Http provider.

        Args:
            http: The Http instance to use for the request.

        Returns:
            str: The user token.
        """
        url = self.typed_properties.token_endpoint
        headers = {"Content-type": "application/json"}
        data = {
            self.typed_properties.username_key_name: self.typed_properties.username_key_value,
            self.typed_properties.password_key_name: self.typed_properties.password_key_value,
        }
        if not url:
            raise ValueError("Token endpoint is missing in the linked service properties")

        try:
            response = http.post(
                url=url,
                headers=headers,
                json=data,
                timeout=30,
            )
            token = find_keys_in_json(response.json(), {"access_token", "accessToken", "token"})
            if token is None:
                raise ValueError("Token not found in response")
        except HTTPError as exc:
            raise AuthenticationError(
                message=f"Authentication error: {exc}",
                details={
                    "http_status_code": exc.response.status_code,
                    "http_response_body": exc.response.text,
                },
            ) from exc
        except Exception as exc:
            raise AuthenticationError(
                message=f"Authentication error: {exc}",
                details={
                    "error_type": type(exc).__name__,
                    "error_message": str(exc),
                },
            ) from exc

        return token

    def _fetch_oauth2_token(self, http: Http) -> str:
        """
        Fetch an OAuth2 token from the token endpoint using the Http provider.

        Args:
            http: The Http instance to use for the request.

        Returns:
            str: The OAuth2 token.
        """
        url = self.typed_properties.token_endpoint
        headers = {"Content-type": "application/x-www-form-urlencoded"}
        data = {
            "client_id": self.typed_properties.client_id,
            "client_secret": self.typed_properties.client_secret,
            "scope": self.typed_properties.scope,
            "grant_type": "client_credentials",
        }
        if not url:
            raise ValueError("Token endpoint is missing in the linked service properties")

        try:
            response = http.post(
                url=url,
                headers=headers,
                data=data,
                timeout=30,
            )
            token = find_keys_in_json(response.json(), {"access_token", "accessToken", "token"})
            if token is None:
                raise ValueError("Token not found in response")
        except HTTPError as exc:
            raise AuthenticationError(
                message=f"Authentication error: {exc}",
                details={
                    "http_status_code": exc.response.status_code,
                    "http_response_body": exc.response.text,
                },
            ) from exc
        except Exception as exc:
            raise AuthenticationError(
                message=f"Authentication error: {exc}",
                details={
                    "error_type": type(exc).__name__,
                    "error_message": str(exc),
                },
            ) from exc

        return token

    def _configure_bearer_auth(self, http: Http) -> None:
        """
        Configure Bearer authentication.

        Fetches a user token via `_fetch_user_token` and sets the session's
        Authorization header.

        Args:
            http: The Http client instance to configure.
        """
        user_access_token = self._fetch_user_token(http)
        http.session.headers.update({"Authorization": f"Bearer {user_access_token}"})

    def _configure_oauth2_auth(self, http: Http) -> None:
        """
        Configure OAuth2 (client credentials) authentication.

        Fetches an OAuth2 token via `_fetch_oauth2_token` and sets the session's
        Authorization header.

        Args:
            http: The Http client instance to configure.
        """
        oauth2_access_token = self._fetch_oauth2_token(http)
        http.session.headers.update({"Authorization": f"Bearer {oauth2_access_token}"})

    def _configure_basic_auth(self, http: Http) -> None:
        """
        Configure HTTP Basic authentication.

        Uses `username_key_value` and `password_key_value` to construct a
        base64-encoded `username:password` token and sets the session's
        Authorization header.

        Args:
            http: The Http client instance to configure.

        Raises:
            ValueError: If username or password is missing.
        """
        username = self.typed_properties.username_key_value
        password = self.typed_properties.password_key_value
        if not username:
            raise ValueError("Basic auth username is missing in the linked service")
        if not password:
            raise ValueError("Basic auth password is missing in the linked service")
        token = base64.b64encode(f"{username}:{password}".encode()).decode("ascii")
        http.session.headers.update({"Authorization": f"Basic {token}"})

    def _configure_apikey_auth(self, http: Http) -> None:
        """
        Configure API key authentication.

        Updates the session headers with the configured API key name/value.

        Args:
            http: The Http client instance to configure.

        Raises:
            ValueError: If API key name or value is missing.
        """
        if not self.typed_properties.api_key_name:
            raise ValueError("API key name is missing in the linked service")
        if not self.typed_properties.api_key_value:
            raise ValueError("API key value is missing in the linked service")
        http.session.headers.update({self.typed_properties.api_key_name: self.typed_properties.api_key_value})

    def _configure_custom_auth(self, http: Http) -> None:
        """
        Configure custom authentication.

        Calls the configured token endpoint and extracts an access token from the
        JSON response using common token key names. The resulting token is stored
        in the session Authorization header.

        Args:
            http: The Http client instance to configure.

        Raises:
            ValueError: If token endpoint is missing or the token cannot be found.
        """
        if not self.typed_properties.token_endpoint:
            raise ValueError("Token endpoint is missing in the linked service properties")
        response = http.post(
            url=self.typed_properties.token_endpoint,
            headers=self.typed_properties.headers,
            json=self.typed_properties.data,
            timeout=30,
        )

        access_token = find_keys_in_json(
            response.json(),
            {
                "access_token",
                "accessToken",
                "token",
            },
        )
        if not access_token:
            raise ValueError("Access token is missing in the response from the token endpoint")
        http.session.headers.update({"Authorization": f"Bearer {access_token}"})

    def _configure_noauth(self, _http: Http) -> None:
        """
        Configure no authentication.

        This is a no-op handler used to keep the auth dispatch table fully typed.

        Args:
            _http: The Http client instance to configure.
        """

        return

    def connect(self) -> Http:
        """
        Connect to the REST API and configure authentication.

        Returns:
            Http: The Http client instance with authentication configured.
        """
        if self._http is None:
            raise RuntimeError("Http instance not initialized. This should not happen.")

        if self._auth_configured:
            return self._http

        handlers = {
            "Bearer": self._configure_bearer_auth,
            "OAuth2": self._configure_oauth2_auth,
            "Basic": self._configure_basic_auth,
            "APIKey": self._configure_apikey_auth,
            "Custom": self._configure_custom_auth,
            "NoAuth": self._configure_noauth,
        }

        try:
            handlers[self.typed_properties.auth_type](self._http)
        except KeyError as exc:
            raise ValueError(f"Unsupported auth_type: {self.typed_properties.auth_type}") from exc

        if self.typed_properties.headers:
            self._http.session.headers.update(self.typed_properties.headers)

        self._auth_configured = True
        return self._http

    def test_connection(self) -> tuple[bool, str]:
        """
        Test the connection to the HTTP API.

        Returns:
            tuple[bool, str]: A tuple containing a boolean indicating success and a string message.
        """
        try:
            http = self.connect()
            http.get(self.base_uri)
            return True, "Connection successfully tested"
        except Exception as exc:
            return False, str(exc)
