"""
**File:** ``http.py``
**Region:** ``ds_protocol_http_py_lib/linked_service/http``

HTTP Linked Service

This module implements a linked service for HTTP APIs.

Example:
    >>> from ds_protocol_http_py_lib import HttpLinkedService, HttpLinkedServiceSettings
    >>> from ds_protocol_http_py_lib.linked_service import OAuth2AuthSettings
    >>> from ds_protocol_http_py_lib.enums import AuthType
    >>> linked_service = HttpLinkedService(
    ...     settings=HttpLinkedServiceSettings(
    ...         host="api.example.com",
    ...         auth_type=AuthType.OAUTH2,
    ...         oauth2=OAuth2AuthSettings(
    ...             token_endpoint="https://auth.example.com/token",
    ...             client_id="my-client",
    ...             client_secret="secret",
    ...         ),
    ...     ),
    ... )
    >>> linked_service.connect()
"""

import base64
from dataclasses import dataclass, field
from typing import Generic, TypeVar

from ds_resource_plugin_py_lib.common.resource.linked_service import (
    LinkedService,
    LinkedServiceSettings,
)
from ds_resource_plugin_py_lib.common.resource.linked_service.errors import (
    AuthenticationError,
    LinkedServiceException,
)

from .. import PACKAGE_NAME, __version__
from ..enums import AuthType, ResourceType
from ..utils import find_keys_in_json
from ..utils.http.config import HttpConfig, RetryConfig
from ..utils.http.provider import Http
from ..utils.http.token_bucket import TokenBucket


@dataclass(kw_only=True)
class ApiKeyAuthSettings:
    """
    Settings for API Key authentication.

    The API key will be added as a header to all requests.
    """

    name: str
    """The header name for the API key (e.g., 'X-API-Key', 'Authorization')."""

    value: str = field(metadata={"mask": True})
    """The API key value. Masked in logs."""


@dataclass(kw_only=True)
class BasicAuthSettings:
    """
    Settings for HTTP Basic authentication.

    Uses standard HTTP Basic auth with base64-encoded username:password.
    """

    username: str
    """The username for basic auth."""

    password: str = field(metadata={"mask": True})
    """The password for basic auth."""


@dataclass(kw_only=True)
class BearerAuthSettings:
    """
    Settings for Bearer token authentication.

    Fetches a token by posting username/password to a token endpoint,
    then uses the returned token as a Bearer token for subsequent requests.
    """

    token_endpoint: str
    """The URL to fetch the bearer token from."""

    username: str
    """The username value to send in the token request."""

    password: str = field(metadata={"mask": True})
    """The password value to send in the token request."""

    username_key_name: str = "email"
    """The JSON key name for username in the token request body."""

    password_key_name: str = "password"
    """The JSON key name for password in the token request body."""


@dataclass(kw_only=True)
class OAuth2AuthSettings:
    """
    Settings for OAuth2 client credentials authentication.

    Uses the OAuth2 client credentials flow to obtain an access token.
    """

    token_endpoint: str
    """The OAuth2 token endpoint URL."""

    client_id: str
    """The OAuth2 client ID."""

    client_secret: str = field(metadata={"mask": True})
    """The OAuth2 client secret."""

    scope: str | None = None
    """Optional OAuth2 scope(s)."""


@dataclass(kw_only=True)
class CustomAuthSettings:
    """
    Settings for custom token-based authentication.

    Posts to a token endpoint and extracts the access token from the response.
    Uses the common ``headers`` field from ``HttpLinkedServiceSettings`` for the token request.
    """

    token_endpoint: str
    """The URL to fetch the token from."""

    data: dict[str, str] | None = None
    """Custom JSON data to send with the token request."""


@dataclass(kw_only=True)
class HttpLinkedServiceSettings(LinkedServiceSettings):
    """
    Settings for HTTP linked service connections.

    Provide the appropriate auth settings object based on your auth_type:

    - ``AuthType.API_KEY`` → ``api_key``
    - ``AuthType.BASIC`` → ``basic``
    - ``AuthType.BEARER`` → ``bearer``
    - ``AuthType.OAUTH2`` → ``oauth2``
    - ``AuthType.CUSTOM`` → ``custom``
    - ``AuthType.NO_AUTH`` → (no auth settings needed)

    Example:
        >>> settings = HttpLinkedServiceSettings(
        ...     host="api.example.com",
        ...     auth_type=AuthType.OAUTH2,
        ...     oauth2=OAuth2AuthSettings(
        ...         token_endpoint="https://auth.example.com/token",
        ...         client_id="my-client",
        ...         client_secret="secret",
        ...     ),
        ... )
    """

    # Connection settings
    host: str
    """The API host (e.g., 'api.example.com')."""

    auth_type: AuthType
    """The authentication type to use."""

    schema: str = "https"
    """URL scheme ('http' or 'https')."""

    port: int | None = None
    """Optional port number."""

    headers: dict[str, str] | None = None
    """Additional headers to include with all requests."""

    # Auth-specific settings (provide one based on auth_type)
    api_key: ApiKeyAuthSettings | None = None
    """Settings for API Key authentication. Required when auth_type=AuthType.API_KEY."""

    basic: BasicAuthSettings | None = None
    """Settings for Basic authentication. Required when auth_type=AuthType.BASIC."""

    bearer: BearerAuthSettings | None = None
    """Settings for Bearer token authentication. Required when auth_type=AuthType.BEARER."""

    oauth2: OAuth2AuthSettings | None = None
    """Settings for OAuth2 client credentials authentication. Required when auth_type=AuthType.OAUTH2."""

    custom: CustomAuthSettings | None = None
    """Settings for custom token authentication. Required when auth_type=AuthType.CUSTOM."""


HttpLinkedServiceSettingsType = TypeVar(
    "HttpLinkedServiceSettingsType",
    bound=HttpLinkedServiceSettings,
)


@dataclass(kw_only=True)
class HttpLinkedService(
    LinkedService[HttpLinkedServiceSettingsType],
    Generic[HttpLinkedServiceSettingsType],
):
    """
    The class is used to connect with HTTP API.
    """

    settings: HttpLinkedServiceSettingsType

    connection: Http | None = field(default=None, init=False, repr=False, metadata={"serialize": False})
    _http: Http | None = field(default=None, init=False, repr=False, metadata={"serialize": False})

    def __post_init__(self) -> None:
        self.base_uri = (
            self.settings.host
            if self.settings.host and "://" in self.settings.host
            else f"{self.settings.schema}://{self.settings.host}"
        )

        if self.settings.port:
            self.base_uri = f"{self.settings.host}:{self.settings.port}"

        self._http = self._init_http()

    @property
    def type(self) -> ResourceType:
        """
        Get the type of the linked service.
        Returns:
            ResourceType
        """
        return ResourceType.LINKED_SERVICE

    def _init_http(self) -> Http:
        """
        Initialize the Http client instance with HttpConfig and TokenBucket.

        Creates an Http instance with:
        - HttpConfig using headers from the linked service settings
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
            headers=dict(self.settings.headers or {}),
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

        Raises:
            LinkedServiceException: If bearer settings are missing.
            AuthenticationError: If the token is missing in the response.
        """
        if not self.settings.bearer:
            raise LinkedServiceException(
                message="Bearer auth settings are missing in the linked service settings",
                details={"type": self.type.value},
            )

        url = self.settings.bearer.token_endpoint
        headers = {"Content-type": "application/json"}
        data = {
            self.settings.bearer.username_key_name: self.settings.bearer.username,
            self.settings.bearer.password_key_name: self.settings.bearer.password,
        }

        response = http.post(
            url=url,
            headers=headers,
            json=data,
            timeout=30,
        )
        token = find_keys_in_json(response.json(), {"access_token", "accessToken", "token"})
        if token is None:
            raise AuthenticationError(
                message="Token is missing in the response from the token endpoint",
                details={
                    "type": self.type.value,
                    "response_body": response.text,
                    "reason": response.reason,
                    "url": response.url,
                    "method": response.request.method,
                },
            )

        return token

    def _fetch_oauth2_token(self, http: Http) -> str:
        """
        Fetch an OAuth2 token from the token endpoint using the Http provider.

        Args:
            http: The Http instance to use for the request.

        Returns:
            str: The OAuth2 token.

        Raises:
            LinkedServiceException: If OAuth2 settings are missing.
            AuthenticationError: If the token is missing in the response.
        """
        if not self.settings.oauth2:
            raise LinkedServiceException(
                message="OAuth2 auth settings are missing in the linked service settings",
                details={"type": self.type.value},
            )

        url = self.settings.oauth2.token_endpoint
        headers = {"Content-type": "application/x-www-form-urlencoded"}
        data = {
            "client_id": self.settings.oauth2.client_id,
            "client_secret": self.settings.oauth2.client_secret,
            "scope": self.settings.oauth2.scope,
            "grant_type": "client_credentials",
        }

        response = http.post(
            url=url,
            headers=headers,
            data=data,
            timeout=30,
        )
        token = find_keys_in_json(response.json(), {"access_token", "accessToken", "token"})
        if token is None:
            raise AuthenticationError(
                message="Token is missing in the response from the token endpoint",
                details={
                    "type": self.type.value,
                    "response_body": response.text,
                    "reason": response.reason,
                    "url": response.url,
                    "method": response.request.method,
                },
            )

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

        Uses the basic auth settings to construct a base64-encoded
        `username:password` token and sets the session's Authorization header.

        Args:
            http: The Http client instance to configure.

        Raises:
            LinkedServiceException: If basic auth settings are missing.
        """
        if not self.settings.basic:
            raise LinkedServiceException(
                message="Basic auth settings are missing in the linked service",
                details={"type": self.type.value},
            )

        token = base64.b64encode(f"{self.settings.basic.username}:{self.settings.basic.password}".encode()).decode("ascii")
        http.session.headers.update({"Authorization": f"Basic {token}"})

    def _configure_apikey_auth(self, http: Http) -> None:
        """
        Configure API key authentication.

        Updates the session headers with the configured API key name/value.

        Args:
            http: The Http client instance to configure.

        Raises:
            LinkedServiceException: If API key settings are missing.
        """
        if not self.settings.api_key:
            raise LinkedServiceException(
                message="API key auth settings are missing in the linked service",
                details={"type": self.type.value},
            )

        http.session.headers.update({self.settings.api_key.name: self.settings.api_key.value})

    def _configure_custom_auth(self, http: Http) -> None:
        """
        Configure custom authentication.

        Calls the configured token endpoint and extracts an access token from the
        JSON response using common token key names. The resulting token is stored
        in the session Authorization header.

        Args:
            http: The Http client instance to configure.

        Raises:
            AuthenticationError: If the token is missing in the response.
            LinkedServiceException: If custom auth settings are missing.
        """
        if not self.settings.custom:
            raise LinkedServiceException(
                message="Custom auth settings are missing in the linked service settings",
                details={"type": self.type.value},
            )

        response = http.post(
            url=self.settings.custom.token_endpoint,
            headers=self.settings.headers,
            json=self.settings.custom.data,
            timeout=30,
        )
        token = find_keys_in_json(response.json(), {"access_token", "accessToken", "token"})
        if token is None:
            raise AuthenticationError(
                message="Token is missing in the response from the token endpoint",
                details={
                    "type": self.type.value,
                    "response_body": response.text,
                    "reason": response.reason,
                    "url": response.url,
                    "method": response.request.method,
                },
            )

        http.session.headers.update({"Authorization": f"Bearer {token}"})

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
        Connect to the HTTP API and configure authentication.

        Initializes the Http client instance if not already initialized.
        Configures authentication based on the auth_type.
        Updates the session headers with the configured headers.

        Returns:
            Http: The Http client instance with authentication configured.

        Raises:
            AuthenticationError: If the authentication fails.
            LinkedServiceException: If the auth_type is unsupported.
        """
        if self._http is None:
            self._http = self._init_http()

        handlers = {
            "Bearer": self._configure_bearer_auth,
            "OAuth2": self._configure_oauth2_auth,
            "Basic": self._configure_basic_auth,
            "APIKey": self._configure_apikey_auth,
            "Custom": self._configure_custom_auth,
            "NoAuth": self._configure_noauth,
        }

        try:
            handlers[self.settings.auth_type](self._http)
        except KeyError as exc:
            raise LinkedServiceException(
                message=f"Unsupported auth_type: {self.settings.auth_type}",
                details={
                    "type": self.type.value,
                    "auth_type": self.settings.auth_type,
                    "error_type": type(exc).__name__,
                    "valid_auth_types": list(handlers.keys()),
                },
            ) from exc

        if self.settings.headers:
            self._http.session.headers.update(self.settings.headers)

        self.connection = self._http
        return self.connection

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

    def close(self) -> None:
        """
        Close the linked service.
        """
        if self._http:
            self._http.close()
