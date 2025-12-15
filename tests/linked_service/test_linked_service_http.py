"""
HttpLinkedService behavior tests.

Covers:
- Base URI construction rules (schema/host/port handling).
- Token fetch flows (Bearer and OAuth2), including error handling and token extraction.
- connect() authentication branches (NoAuth/APIKey/Bearer/OAuth2/Custom) and header updates.
- test_connection() success/failure signaling.
"""

from __future__ import annotations

from typing import Any, cast

import pytest
from ds_resource_plugin_py_lib.common.resource.linked_service.errors import AuthenticationException

from ds_protocol_http_py_lib.linked_service.http import HttpLinkedService, HttpLinkedServiceTypedProperties
from tests.mocks import JsonResponse, LinkedServiceHttp, http_error


def test_post_init_builds_base_uri_from_schema_and_host() -> None:
    """
    It prefixes schema when host has no explicit scheme.
    """

    props = HttpLinkedServiceTypedProperties(host="api.example.test", auth_type="NoAuth", schema="https")
    service = HttpLinkedService(typed_properties=props)
    assert service.base_uri == "https://api.example.test"


def test_post_init_uses_host_with_scheme_as_base_uri() -> None:
    """
    It preserves host when scheme is already included.
    """

    props = HttpLinkedServiceTypedProperties(host="http://api.example.test", auth_type="NoAuth")
    service = HttpLinkedService(typed_properties=props)
    assert service.base_uri == "http://api.example.test"


def test_post_init_with_port_uses_host_and_port() -> None:
    """
    It uses host and port when port is provided.
    """

    props = HttpLinkedServiceTypedProperties(host="api.example.test", auth_type="NoAuth", port=8443)
    service = HttpLinkedService(typed_properties=props)
    assert service.base_uri == "api.example.test:8443"


def test_fetch_user_token_requires_token_endpoint() -> None:
    """
    It raises ValueError when token_endpoint is missing.
    """

    props = HttpLinkedServiceTypedProperties(host="api.example.test", auth_type="Bearer", token_endpoint=None)
    service = HttpLinkedService(typed_properties=props)
    http = service._http
    assert http is not None
    with pytest.raises(ValueError):
        service._fetch_user_token(http)


def test_fetch_user_token_raises_authentication_exception_on_http_error() -> None:
    """
    It wraps HTTPError into AuthenticationException with response details.
    """

    props = HttpLinkedServiceTypedProperties(
        host="api.example.test",
        auth_type="Bearer",
        token_endpoint="https://example.test/token",
        username_key_value="u",
        password_key_value="p",
    )
    service = HttpLinkedService(typed_properties=props)
    fake_http = LinkedServiceHttp(session=type("S", (), {"headers": {}})(), post_error=http_error(401, "nope"))
    with pytest.raises(AuthenticationException) as exc_info:
        service._fetch_user_token(cast("Any", fake_http))
    assert exc_info.value.details["http_status_code"] == 401


def test_fetch_user_token_raises_authentication_exception_when_token_is_missing() -> None:
    """
    It raises AuthenticationException when the response JSON has no token field.
    """

    props = HttpLinkedServiceTypedProperties(
        host="api.example.test",
        auth_type="Bearer",
        token_endpoint="https://example.test/token",
        username_key_value="u",
        password_key_value="p",
    )
    service = HttpLinkedService(typed_properties=props)
    fake_http = LinkedServiceHttp(session=type("S", (), {"headers": {}})(), post_response=JsonResponse({"x": "y"}))
    with pytest.raises(AuthenticationException) as exc_info:
        service._fetch_user_token(cast("Any", fake_http))
    assert exc_info.value.details["error_type"] == "ValueError"


def test_fetch_oauth2_token_extracts_token_from_json(token_payloads) -> None:
    """
    It extracts a token from common JSON key variations.
    """

    props = HttpLinkedServiceTypedProperties(
        host="api.example.test",
        auth_type="OAuth2",
        token_endpoint="https://example.test/token",
        client_id="id",
        client_secret="secret",
        scope="s",
    )
    service = HttpLinkedService(typed_properties=props)
    response = JsonResponse(token_payloads["flat_accessToken"])
    fake_http = LinkedServiceHttp(session=type("S", (), {"headers": {}})(), post_response=response)
    token = service._fetch_oauth2_token(cast("Any", fake_http))
    assert token == "t2"


def test_fetch_oauth2_token_requires_token_endpoint() -> None:
    """
    It raises ValueError when token_endpoint is missing.
    """

    props = HttpLinkedServiceTypedProperties(
        host="api.example.test",
        auth_type="OAuth2",
        token_endpoint=None,
        client_id="id",
        client_secret="secret",
        scope="s",
    )
    service = HttpLinkedService(typed_properties=props)
    http = service._http
    assert http is not None
    with pytest.raises(ValueError):
        service._fetch_oauth2_token(http)


def test_fetch_oauth2_token_raises_authentication_exception_when_token_is_missing() -> None:
    """
    It raises AuthenticationException when the response JSON has no token field.
    """

    props = HttpLinkedServiceTypedProperties(
        host="api.example.test",
        auth_type="OAuth2",
        token_endpoint="https://example.test/token",
        client_id="id",
        client_secret="secret",
        scope="s",
    )
    service = HttpLinkedService(typed_properties=props)
    fake_http = LinkedServiceHttp(session=type("S", (), {"headers": {}})(), post_response=JsonResponse({"x": "y"}))
    with pytest.raises(AuthenticationException) as exc_info:
        service._fetch_oauth2_token(cast("Any", fake_http))
    assert exc_info.value.details["error_type"] == "ValueError"


def test_connect_apikey_updates_session_headers() -> None:
    """
    It sets the API key header when auth_type is APIKey.
    """

    props = HttpLinkedServiceTypedProperties(
        host="api.example.test",
        auth_type="APIKey",
        api_key_name="X-API-Key",
        api_key_value="k",
    )
    service = HttpLinkedService(typed_properties=props)
    http = service.connect()
    assert http.session.headers["X-API-Key"] == "k"
    assert service._auth_configured is True


def test_connect_apikey_requires_name_and_value() -> None:
    """
    It raises ValueError when API key name or value is missing.
    """

    props_missing_name = HttpLinkedServiceTypedProperties(
        host="api.example.test",
        auth_type="APIKey",
        api_key_name=None,
        api_key_value="k",
    )
    service_missing_name = HttpLinkedService(typed_properties=props_missing_name)
    with pytest.raises(ValueError):
        service_missing_name.connect()

    props_missing_value = HttpLinkedServiceTypedProperties(
        host="api.example.test",
        auth_type="APIKey",
        api_key_name="X",
        api_key_value=None,
    )
    service_missing_value = HttpLinkedService(typed_properties=props_missing_value)
    with pytest.raises(ValueError):
        service_missing_value.connect()


def test_connect_bearer_sets_authorization_header(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    It stores the fetched bearer token in the Authorization header.
    """

    props = HttpLinkedServiceTypedProperties(
        host="api.example.test",
        auth_type="Bearer",
        token_endpoint="https://example.test/token",
    )
    service = HttpLinkedService(typed_properties=props)
    monkeypatch.setattr(service, "_fetch_user_token", lambda http: "bt")
    http = service.connect()
    assert http.session.headers["Authorization"] == "Bearer bt"


def test_connect_oauth2_sets_authorization_header(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    It stores the fetched OAuth2 token in the Authorization header.
    """

    props = HttpLinkedServiceTypedProperties(
        host="api.example.test",
        auth_type="OAuth2",
        token_endpoint="https://example.test/token",
        client_id="id",
        client_secret="secret",
        scope="s",
    )
    service = HttpLinkedService(typed_properties=props)
    monkeypatch.setattr(service, "_fetch_oauth2_token", lambda http: "ot")
    http = service.connect()
    assert http.session.headers["Authorization"] == "Bearer ot"


def test_connect_custom_requires_token_endpoint() -> None:
    """
    It raises ValueError when Custom auth is configured without token endpoint.
    """

    props = HttpLinkedServiceTypedProperties(host="api.example.test", auth_type="Custom", token_endpoint=None)
    service = HttpLinkedService(typed_properties=props)
    with pytest.raises(ValueError):
        service.connect()


def test_connect_custom_sets_bearer_authorization_header(token_payloads) -> None:
    """
    It calls the token endpoint and stores the returned token in Authorization header.
    """

    props = HttpLinkedServiceTypedProperties(
        host="api.example.test",
        auth_type="Custom",
        token_endpoint="https://example.test/token",
        headers={"Content-type": "application/json"},
        data={"x": "y"},
    )
    service = HttpLinkedService(typed_properties=props)
    fake_session = type("S", (), {"headers": {}})()
    service._http = cast("Any", LinkedServiceHttp(session=fake_session, post_response=JsonResponse(token_payloads["flat_token"])))
    http = service.connect()
    assert http.session.headers["Authorization"] == "Bearer t3"


def test_connect_custom_raises_when_access_token_is_missing() -> None:
    """
    It raises ValueError when the token endpoint response does not include a token.
    """

    props = HttpLinkedServiceTypedProperties(
        host="api.example.test",
        auth_type="Custom",
        token_endpoint="https://example.test/token",
        headers={"Content-type": "application/json"},
        data={"x": "y"},
    )
    service = HttpLinkedService(typed_properties=props)
    fake_session = type("S", (), {"headers": {}})()
    service._http = cast("Any", LinkedServiceHttp(session=fake_session, post_response=JsonResponse({"x": "y"})))
    with pytest.raises(ValueError):
        service.connect()


def test_connect_noauth_only_merges_headers() -> None:
    """
    It does not add auth headers for NoAuth but merges configured headers.
    """

    props = HttpLinkedServiceTypedProperties(host="api.example.test", auth_type="NoAuth", headers={"X-Test": "1"})
    service = HttpLinkedService(typed_properties=props)
    http = service.connect()
    assert http.session.headers["X-Test"] == "1"


def test_connect_is_idempotent_after_first_configuration() -> None:
    """
    It does not reconfigure auth on subsequent connect calls.
    """

    props = HttpLinkedServiceTypedProperties(host="api.example.test", auth_type="NoAuth", headers={"X-Test": "1"})
    service = HttpLinkedService(typed_properties=props)
    http1 = service.connect()
    http1.session.headers["X-Once"] = "yes"
    http2 = service.connect()
    assert http2.session.headers["X-Once"] == "yes"


def test_test_connection_returns_false_on_exception() -> None:
    """
    It returns (False, error) when the underlying request fails.
    """

    props = HttpLinkedServiceTypedProperties(host="api.example.test", auth_type="NoAuth")
    service = HttpLinkedService(typed_properties=props)
    service._http = cast(
        "Any",
        LinkedServiceHttp(session=type("S", (), {"headers": {}})(), get_error=RuntimeError("down")),
    )
    ok, message = service.test_connection()
    assert ok is False
    assert "down" in message


def test_test_connection_returns_true_on_success() -> None:
    """
    It returns (True, success_message) when the GET succeeds.
    """

    props = HttpLinkedServiceTypedProperties(host="api.example.test", auth_type="NoAuth")
    service = HttpLinkedService(typed_properties=props)
    service._http = cast("Any", LinkedServiceHttp(session=type("S", (), {"headers": {}})()))
    ok, message = service.test_connection()
    assert ok is True
    assert "successfully" in message


def test_connect_raises_when_http_is_not_initialized() -> None:
    """
    It raises RuntimeError if the internal Http client is missing.
    """

    props = HttpLinkedServiceTypedProperties(host="api.example.test", auth_type="NoAuth")
    service = HttpLinkedService(typed_properties=props)
    service._http = None
    with pytest.raises(RuntimeError):
        service.connect()
