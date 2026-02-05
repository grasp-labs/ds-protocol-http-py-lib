"""
**File:** ``test_enums.py``
**Region:** ``tests/test_enums``

Enum contract tests.

Covers:
- Stability of ResourceType string values.
- String-like behavior for serialization and logging.
"""

from __future__ import annotations

from ds_protocol_http_py_lib.enums import AuthType, HttpMethod, ResourceType


def test_resource_type_values_are_stable() -> None:
    """
    It defines stable string values for resource types.
    """

    assert ResourceType.LINKED_SERVICE == "DS.RESOURCE.LINKED_SERVICE.HTTP"
    assert ResourceType.DATASET == "DS.RESOURCE.DATASET.HTTP"


def test_resource_type_is_string_like() -> None:
    """
    It behaves like a string for serialization purposes.
    """

    assert str(ResourceType.DATASET) == "DS.RESOURCE.DATASET.HTTP"


def test_http_method_values_are_stable() -> None:
    """
    It defines stable string values for HTTP methods.
    """

    assert HttpMethod.GET == "GET"
    assert HttpMethod.POST == "POST"
    assert HttpMethod.PUT == "PUT"
    assert HttpMethod.DELETE == "DELETE"
    assert HttpMethod.PATCH == "PATCH"


def test_http_auth_type_values_are_stable() -> None:
    """
    It defines stable string values for HTTP authentication types.
    """

    assert AuthType.OAUTH2 == "OAuth2"
    assert AuthType.BASIC == "Basic"
    assert AuthType.API_KEY == "APIKey"
    assert AuthType.BEARER == "Bearer"
    assert AuthType.NO_AUTH == "NoAuth"
    assert AuthType.CUSTOM == "Custom"
