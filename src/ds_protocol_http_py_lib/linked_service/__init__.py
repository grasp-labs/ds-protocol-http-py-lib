"""
**File:** ``__init__.py``
**Region:** ``ds_protocol_http_py_lib/linked_service``

HTTP Linked Service

This module implements a linked service for HTTP APIs.

Example:
    >>> from ds_protocol_http_py_lib.enums import AuthType
    >>> linked_service = HttpLinkedService(
    ...     id=uuid.uuid4(),
    ...     name="example::linked_service",
    ...     version="1.0.0",
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

from .http import (
    ApiKeyAuthSettings,
    BasicAuthSettings,
    BearerAuthSettings,
    CustomAuthSettings,
    HttpLinkedService,
    HttpLinkedServiceSettings,
    OAuth2AuthSettings,
)

__all__ = [
    "ApiKeyAuthSettings",
    "BasicAuthSettings",
    "BearerAuthSettings",
    "CustomAuthSettings",
    "HttpLinkedService",
    "HttpLinkedServiceSettings",
    "OAuth2AuthSettings",
]
