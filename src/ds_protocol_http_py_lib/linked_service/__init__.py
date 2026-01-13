"""
**File:** ``__init__.py``
**Region:** ``ds_protocol_http_py_lib/linked_service``

HTTP Linked Service

This module implements a linked service for HTTP APIs.

Example:
    >>> linked_service = HttpLinkedService(
    ...     typed_properties=HttpLinkedServiceTypedProperties(
    ...         host="https://api.example.com",
    ...         auth_type="OAuth2",
    ...         client_id="",
    ...         client_secret="",
    ...         token_endpoint="https://api.example.com/token",
    ...     ),
    ... )
    >>> linked_service.connect()
"""

from .http import HttpLinkedService, HttpLinkedServiceTypedProperties

__all__ = [
    "HttpLinkedService",
    "HttpLinkedServiceTypedProperties",
]
