"""
**File:** ``http.py``
**Region:** ``ds_protocol_http_py_lib/linked_service/http``

HTTP Linked Service

This module implements a linked service for HTTP APIs.

Example:
    >>> linked_service = HttpLinkedService(
    ...     settings=HttpLinkedServiceSettings(
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
    LinkedServiceSettings,
)
from ds_resource_plugin_py_lib.common.resource.linked_service.errors import (
    AuthenticationError,
    LinkedServiceException,
)

from .. import PACKAGE_NAME, __version__
from ..enums import ResourceType
from ..utils import find_keys_in_json
from ..utils.http.config import HttpConfig, RetryConfig
from ..utils.http.provider import Http
from ..utils.http.token_bucket import TokenBucket


@dataclass(kw_only=True)
class HttpLinkedServiceSettings(LinkedServiceSettings):
    """
    The object containing the HTTP linked service settings.
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

    connection: Http | None = field(default=None, init=False)
    _http: Http | None = field(default=None, init=False)

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
            LinkedServiceException: If the token endpoint is missing.
            AuthenticationError: If the token is missing in the response.
        """
        url = self.settings.token_endpoint
        headers = {"Content-type": "application/json"}
        data = {
            self.settings.username_key_name: self.settings.username_key_value,
            self.settings.password_key_name: self.settings.password_key_value,
        }
        if not url:
            raise LinkedServiceException(
                message="Token endpoint is missing in the linked service settings",
                details={"type": self.type.value},
            )

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
            LinkedServiceException: If the token endpoint is missing.
            AuthenticationError: If the token is missing in the response.
        """
        url = self.settings.token_endpoint
        headers = {"Content-type": "application/x-www-form-urlencoded"}
        data = {
            "client_id": self.settings.client_id,
            "client_secret": self.settings.client_secret,
            "scope": self.settings.scope,
            "grant_type": "client_credentials",
        }
        if not url:
            raise LinkedServiceException(
                message="Token endpoint is missing in the linked service settings",
                details={"type": self.type.value},
            )

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

        Uses `username_key_value` and `password_key_value` to construct a
        base64-encoded `username:password` token and sets the session's
        Authorization header.

        Args:
            http: The Http client instance to configure.

        Raises:
            LinkedServiceException: If username or password is missing.
        """
        username = self.settings.username_key_value
        password = self.settings.password_key_value
        if not username:
            raise LinkedServiceException(
                message="Basic auth username is missing in the linked service",
                details={"type": self.type.value},
            )
        if not password:
            raise LinkedServiceException(
                message="Basic auth password is missing in the linked service",
                details={"type": self.type.value},
            )
        token = base64.b64encode(f"{username}:{password}".encode()).decode("ascii")
        http.session.headers.update({"Authorization": f"Basic {token}"})

    def _configure_apikey_auth(self, http: Http) -> None:
        """
        Configure API key authentication.

        Updates the session headers with the configured API key name/value.

        Args:
            http: The Http client instance to configure.

        Raises:
            LinkedServiceException: If API key name or value is missing.
        """
        if not self.settings.api_key_name:
            raise LinkedServiceException(
                message="API key name is missing in the linked service",
                details={"type": self.type.value},
            )
        if not self.settings.api_key_value:
            raise LinkedServiceException(
                message="API key value is missing in the linked service",
                details={"type": self.type.value},
            )
        http.session.headers.update({self.settings.api_key_name: self.settings.api_key_value})

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
            LinkedServiceException: If token endpoint is missing or the token cannot be found.
        """
        if not self.settings.token_endpoint:
            raise LinkedServiceException(
                message="Token endpoint is missing in the linked service settings",
                details={"type": self.type.value},
            )

        response = http.post(
            url=self.settings.token_endpoint,
            headers=self.settings.headers,
            json=self.settings.data,
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
