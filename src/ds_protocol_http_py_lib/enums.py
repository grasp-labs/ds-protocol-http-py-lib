"""
**File:** ``enums.py``
**Region:** ``ds_protocol_http_py_lib/enums``

Constants for HTTP protocol.

Example:
    >>> ResourceType.LINKED_SERVICE
    'DS.RESOURCE.LINKED_SERVICE.HTTP'
    >>> ResourceType.DATASET
    'DS.RESOURCE.DATASET.HTTP'
"""

from enum import StrEnum


class HttpMethod(StrEnum):
    """
    Constants for HTTP methods.
    """

    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"
    PATCH = "PATCH"


class AuthType(StrEnum):
    """
    Constants for authentication types.
    """

    OAUTH2 = "OAuth2"
    BASIC = "Basic"
    API_KEY = "APIKey"
    BEARER = "Bearer"
    NO_AUTH = "NoAuth"
    CUSTOM = "Custom"


class ResourceType(StrEnum):
    """
    Constants for HTTP protocol.
    """

    LINKED_SERVICE = "DS.RESOURCE.LINKED_SERVICE.HTTP"
    DATASET = "DS.RESOURCE.DATASET.HTTP"
