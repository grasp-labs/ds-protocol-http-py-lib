from dataclasses import dataclass, field
from typing import Generic, Literal, TypeVar

from ds_resource_plugin_py_lib.common.resource.linked_service import (
    LinkedService,
    LinkedServiceTypedProperties,
)
from ds_resource_plugin_py_lib.common.resource.linked_service.errors import (
    AuthenticationException,
)
from requests import HTTPError

from .. import __name__, __version__
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
            allowed_methods=("GET", "POST"),
            raise_on_status=False,
            respect_retry_after_header=True,
        )
        config = HttpConfig(
            headers=dict(self.typed_properties.headers or {}),
            timeout_seconds=30,
            user_agent=f"{__name__}/{__version__}",
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
            raise AuthenticationException(
                message=f"Authentication error: {exc}",
                details={
                    "http_status_code": exc.response.status_code,
                    "http_response_body": exc.response.text,
                },
            ) from exc
        except Exception as exc:
            raise AuthenticationException(
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
            raise AuthenticationException(
                message=f"Authentication error: {exc}",
                details={
                    "http_status_code": exc.response.status_code,
                    "http_response_body": exc.response.text,
                },
            ) from exc
        except Exception as exc:
            raise AuthenticationException(
                message=f"Authentication error: {exc}",
                details={
                    "error_type": type(exc).__name__,
                    "error_message": str(exc),
                },
            ) from exc

        return token

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

        if self.typed_properties.auth_type == "Bearer":
            user_access_token = self._fetch_user_token(self._http)
            self._http.session.headers.update({"Authorization": f"Bearer {user_access_token}"})
        elif self.typed_properties.auth_type == "OAuth2":
            oauth2_access_token = self._fetch_oauth2_token(self._http)
            self._http.session.headers.update({"Authorization": f"Bearer {oauth2_access_token}"})
        elif self.typed_properties.auth_type == "APIKey":
            if not self.typed_properties.api_key_name:
                raise ValueError("API key name is missing in the linked service")
            if not self.typed_properties.api_key_value:
                raise ValueError("API key value is missing in the linked service")
            self._http.session.headers.update({self.typed_properties.api_key_name: self.typed_properties.api_key_value})
        elif self.typed_properties.auth_type == "Custom":
            if not self.typed_properties.token_endpoint:
                raise ValueError("Token endpoint is missing in the linked service properties")
            response = self._http.post(
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
            self._http.session.headers.update({"Authorization": f"Bearer {access_token}"})
        elif self.typed_properties.auth_type == "NoAuth":
            pass

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
