"""
**File:** ``test_linked_service_http.py``
**Region:** ``tests/linked_service/test_linked_service_http``

HttpLinkedService behavior tests.

Covers:
- Base URI construction rules (schema/host/port handling).
- Token fetch flows (Bearer and OAuth2), including error handling and token extraction.
- connect() authentication branches (NoAuth/APIKey/Basic/Bearer/OAuth2/Custom) and header updates.
- test_connection() success/failure signaling.
"""

from __future__ import annotations

import base64
import uuid
from typing import Any, cast

import pytest
from ds_resource_plugin_py_lib.common.resource.linked_service.errors import (
    AuthenticationError,
    LinkedServiceException,
)

from ds_protocol_http_py_lib.enums import AuthType
from ds_protocol_http_py_lib.linked_service.http import (
    ApiKeyAuthSettings,
    BasicAuthSettings,
    BearerAuthSettings,
    CustomAuthSettings,
    HttpLinkedService,
    HttpLinkedServiceSettings,
    OAuth2AuthSettings,
)
from tests.mocks import LinkedServiceHttp, json_response


def test_post_init_builds_base_uri_from_schema_and_host() -> None:
    """
    It prefixes schema when host has no explicit scheme.
    """

    props = HttpLinkedServiceSettings(host="api.example.test", auth_type=AuthType.NO_AUTH, schema="https")
    service = HttpLinkedService(id=uuid.uuid4(), name="test-name", version="1.0.0", settings=props)
    assert service.base_uri == "https://api.example.test"


def test_post_init_uses_host_with_scheme_as_base_uri() -> None:
    """
    It preserves host when scheme is already included.
    """

    props = HttpLinkedServiceSettings(host="http://api.example.test", auth_type=AuthType.NO_AUTH)
    service = HttpLinkedService(id=uuid.uuid4(), name="test-name", version="1.0.0", settings=props)
    assert service.base_uri == "http://api.example.test"


def test_post_init_with_port_uses_host_and_port() -> None:
    """
    It uses host and port when port is provided.
    """

    props = HttpLinkedServiceSettings(host="api.example.test", auth_type=AuthType.NO_AUTH, port=8443)
    service = HttpLinkedService(id=uuid.uuid4(), name="test-name", version="1.0.0", settings=props)
    assert service.base_uri == "api.example.test:8443"


def test_connect_initializes_http_when_missing() -> None:
    """
    It (re)initializes the internal Http client if _http is None.
    """
    props = HttpLinkedServiceSettings(host="api.example.test", auth_type=AuthType.NO_AUTH)
    service = HttpLinkedService(id=uuid.uuid4(), name="test-name", version="1.0.0", settings=props)
    service._http = None
    http = service.connect()
    assert http is not None


def test_connect_raises_for_unsupported_auth_type() -> None:
    """
    It raises LinkedServiceException for unknown auth_type values.
    """
    props = HttpLinkedServiceSettings(host="api.example.test", auth_type=cast("Any", "WeirdAuth"))
    service = HttpLinkedService(id=uuid.uuid4(), name="test-name", version="1.0.0", settings=props)
    with pytest.raises(LinkedServiceException):
        service.connect()


def test_fetch_user_token_requires_bearer_settings() -> None:
    """
    It raises LinkedServiceException when bearer settings are missing.
    """

    props = HttpLinkedServiceSettings(host="api.example.test", auth_type=AuthType.BEARER, bearer=None)
    service = HttpLinkedService(id=uuid.uuid4(), name="test-name", version="1.0.0", settings=props)
    http = service._http
    assert http is not None
    with pytest.raises(LinkedServiceException):
        service._fetch_user_token(http)


def test_fetch_user_token_raises_authentication_exception_on_http_error() -> None:
    """
    It propagates AuthenticationError raised by the underlying HTTP client.
    """

    props = HttpLinkedServiceSettings(
        host="api.example.test",
        auth_type=AuthType.BEARER,
        bearer=BearerAuthSettings(
            token_endpoint="https://example.test/token",
            username="u",
            password="p",
        ),
    )
    service = HttpLinkedService(id=uuid.uuid4(), name="test-name", version="1.0.0", settings=props)
    fake_http = LinkedServiceHttp(
        session=type("S", (), {"headers": {}})(),
        post_error=AuthenticationError(
            message="Authentication error: boom",
            details={
                "url": props.bearer.token_endpoint if props.bearer else "",
                "method": "POST",
            },
        ),
    )
    with pytest.raises(AuthenticationError):
        service._fetch_user_token(cast("Any", fake_http))


def test_fetch_user_token_raises_authentication_exception_when_token_is_missing() -> None:
    """
    It raises AuthenticationError when the response JSON has no token field.
    """

    props = HttpLinkedServiceSettings(
        host="api.example.test",
        auth_type=AuthType.BEARER,
        bearer=BearerAuthSettings(
            token_endpoint="https://example.test/token",
            username="u",
            password="p",
        ),
    )
    service = HttpLinkedService(id=uuid.uuid4(), name="test-name", version="1.0.0", settings=props)
    fake_http = LinkedServiceHttp(
        session=type("S", (), {"headers": {}})(),
        post_response=json_response(
            {"x": "y"},
            url="https://example.test/token",
            method="POST",
            reason="OK",
        ),
    )
    with pytest.raises(AuthenticationError) as exc_info:
        service._fetch_user_token(cast("Any", fake_http))
    assert exc_info.value.details["url"] == "https://example.test/token"
    assert exc_info.value.details["method"] == "POST"
    assert "x" in str(exc_info.value.details["response_body"])


def test_fetch_oauth2_token_extracts_token_from_json(token_payloads) -> None:
    """
    It extracts a token from common JSON key variations.
    """

    props = HttpLinkedServiceSettings(
        host="api.example.test",
        auth_type=AuthType.OAUTH2,
        oauth2=OAuth2AuthSettings(
            token_endpoint="https://example.test/token",
            client_id="id",
            client_secret="secret",
            scope="s",
        ),
    )
    service = HttpLinkedService(id=uuid.uuid4(), name="test-name", version="1.0.0", settings=props)
    response = json_response(token_payloads["flat_accessToken"], url="https://example.test/token", method="POST")
    fake_http = LinkedServiceHttp(session=type("S", (), {"headers": {}})(), post_response=response)
    token = service._fetch_oauth2_token(cast("Any", fake_http))
    assert token == "t2"


def test_fetch_oauth2_token_requires_oauth2_settings() -> None:
    """
    It raises LinkedServiceException when OAuth2 settings are missing.
    """

    props = HttpLinkedServiceSettings(
        host="api.example.test",
        auth_type=AuthType.OAUTH2,
        oauth2=None,
    )
    service = HttpLinkedService(id=uuid.uuid4(), name="test-name", version="1.0.0", settings=props)
    http = service._http
    assert http is not None
    with pytest.raises(LinkedServiceException):
        service._fetch_oauth2_token(http)


def test_fetch_oauth2_token_raises_authentication_exception_when_token_is_missing() -> None:
    """
    It raises AuthenticationError when the response JSON has no token field.
    """

    props = HttpLinkedServiceSettings(
        host="api.example.test",
        auth_type=AuthType.OAUTH2,
        oauth2=OAuth2AuthSettings(
            token_endpoint="https://example.test/token",
            client_id="id",
            client_secret="secret",
            scope="s",
        ),
    )
    service = HttpLinkedService(id=uuid.uuid4(), name="test-name", version="1.0.0", settings=props)
    fake_http = LinkedServiceHttp(
        session=type("S", (), {"headers": {}})(),
        post_response=json_response({"x": "y"}, url="https://example.test/token", method="POST"),
    )
    with pytest.raises(AuthenticationError) as exc_info:
        service._fetch_oauth2_token(cast("Any", fake_http))
    assert exc_info.value.details["url"] == "https://example.test/token"
    assert exc_info.value.details["method"] == "POST"
    assert "x" in str(exc_info.value.details["response_body"])


def test_connect_apikey_updates_session_headers() -> None:
    """
    It sets the API key header when auth_type is APIKey.
    """

    props = HttpLinkedServiceSettings(
        host="api.example.test",
        auth_type=AuthType.API_KEY,
        api_key=ApiKeyAuthSettings(name="X-API-Key", value="k"),
    )
    service = HttpLinkedService(id=uuid.uuid4(), name="test-name", version="1.0.0", settings=props)
    http = service.connect()
    assert service.connection is http
    assert service._http is http
    assert http.session.headers["X-API-Key"] == "k"


def test_connect_apikey_requires_api_key_settings() -> None:
    """
    It raises LinkedServiceException when API key settings are missing.
    """

    props = HttpLinkedServiceSettings(
        host="api.example.test",
        auth_type=AuthType.API_KEY,
        api_key=None,
    )
    service = HttpLinkedService(id=uuid.uuid4(), name="test-name", version="1.0.0", settings=props)
    with pytest.raises(LinkedServiceException):
        service.connect()


def test_connect_basic_sets_authorization_header() -> None:
    """
    It sets an HTTP Basic Authorization header from configured username/password.
    """

    props = HttpLinkedServiceSettings(
        host="api.example.test",
        auth_type=AuthType.BASIC,
        basic=BasicAuthSettings(username="u", password="p"),
    )
    service = HttpLinkedService(id=uuid.uuid4(), name="test-name", version="1.0.0", settings=props)
    http = service.connect()
    assert service.connection is http
    assert service._http is http
    header = str(http.session.headers["Authorization"])
    assert header.startswith("Basic ")
    encoded = header.split(" ", 1)[1].strip()
    assert base64.b64decode(encoded).decode("utf-8") == "u:p"


def test_connect_basic_requires_basic_settings() -> None:
    """
    It raises LinkedServiceException when Basic auth settings are missing.
    """

    props = HttpLinkedServiceSettings(
        host="api.example.test",
        auth_type=AuthType.BASIC,
        basic=None,
    )
    service = HttpLinkedService(id=uuid.uuid4(), name="test-name", version="1.0.0", settings=props)
    with pytest.raises(LinkedServiceException):
        service.connect()


def test_connect_bearer_sets_authorization_header(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    It stores the fetched bearer token in the Authorization header.
    """

    props = HttpLinkedServiceSettings(
        host="api.example.test",
        auth_type=AuthType.BEARER,
        bearer=BearerAuthSettings(
            token_endpoint="https://example.test/token",
            username="u",
            password="p",
        ),
    )
    service = HttpLinkedService(id=uuid.uuid4(), name="test-name", version="1.0.0", settings=props)
    monkeypatch.setattr(service, "_fetch_user_token", lambda http: "bt")
    http = service.connect()
    assert service.connection is http
    assert service._http is http
    assert http.session.headers["Authorization"] == "Bearer bt"


def test_connect_oauth2_sets_authorization_header(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    It stores the fetched OAuth2 token in the Authorization header.
    """

    props = HttpLinkedServiceSettings(
        host="api.example.test",
        auth_type=AuthType.OAUTH2,
        oauth2=OAuth2AuthSettings(
            token_endpoint="https://example.test/token",
            client_id="id",
            client_secret="secret",
            scope="s",
        ),
    )
    service = HttpLinkedService(id=uuid.uuid4(), name="test-name", version="1.0.0", settings=props)
    monkeypatch.setattr(service, "_fetch_oauth2_token", lambda http: "ot")
    http = service.connect()
    assert service.connection is http
    assert service._http is http
    assert http.session.headers["Authorization"] == "Bearer ot"


def test_connect_custom_requires_custom_settings() -> None:
    """
    It raises LinkedServiceException when Custom auth settings are missing.
    """

    props = HttpLinkedServiceSettings(host="api.example.test", auth_type=AuthType.CUSTOM, custom=None)
    service = HttpLinkedService(id=uuid.uuid4(), name="test-name", version="1.0.0", settings=props)
    with pytest.raises(LinkedServiceException):
        service.connect()


def test_connect_custom_sets_bearer_authorization_header(token_payloads) -> None:
    """
    It calls the token endpoint and stores the returned token in Authorization header.
    """

    props = HttpLinkedServiceSettings(
        host="api.example.test",
        auth_type=AuthType.CUSTOM,
        headers={"Content-type": "application/json"},
        custom=CustomAuthSettings(
            token_endpoint="https://example.test/token",
            data={"x": "y"},
        ),
    )
    service = HttpLinkedService(id=uuid.uuid4(), name="test-name", version="1.0.0", settings=props)
    fake_session = type("S", (), {"headers": {}})()
    service._http = cast(
        "Any",
        LinkedServiceHttp(
            session=fake_session,
            post_response=json_response(token_payloads["flat_token"], url="https://example.test/token", method="POST"),
        ),
    )
    http = service.connect()
    assert service.connection is http
    assert http.session.headers["Authorization"] == "Bearer t3"


def test_connect_custom_raises_when_access_token_is_missing() -> None:
    """
    It raises AuthenticationError when the token endpoint response does not include a token.
    """

    props = HttpLinkedServiceSettings(
        host="api.example.test",
        auth_type=AuthType.CUSTOM,
        headers={"Content-type": "application/json"},
        custom=CustomAuthSettings(
            token_endpoint="https://example.test/token",
            data={"x": "y"},
        ),
    )
    service = HttpLinkedService(id=uuid.uuid4(), name="test-name", version="1.0.0", settings=props)
    fake_session = type("S", (), {"headers": {}})()
    service._http = cast(
        "Any",
        LinkedServiceHttp(
            session=fake_session,
            post_response=json_response({"x": "y"}, url="https://example.test/token", method="POST"),
        ),
    )
    with pytest.raises(AuthenticationError) as exc_info:
        service.connect()
    assert exc_info.value.details["url"] == "https://example.test/token"
    assert exc_info.value.details["method"] == "POST"


def test_connect_noauth_only_merges_headers() -> None:
    """
    It does not add auth headers for NoAuth but merges configured headers.
    """

    props = HttpLinkedServiceSettings(host="api.example.test", auth_type=AuthType.NO_AUTH, headers={"X-Test": "1"})
    service = HttpLinkedService(id=uuid.uuid4(), name="test-name", version="1.0.0", settings=props)
    http = service.connect()
    assert http.session.headers["X-Test"] == "1"


def test_connect_is_idempotent_after_first_configuration() -> None:
    """
    It does not reconfigure auth on subsequent connect calls.
    """

    props = HttpLinkedServiceSettings(host="api.example.test", auth_type=AuthType.NO_AUTH, headers={"X-Test": "1"})
    service = HttpLinkedService(id=uuid.uuid4(), name="test-name", version="1.0.0", settings=props)
    http1 = service.connect()
    http1.session.headers["X-Once"] = "yes"
    http2 = service.connect()
    assert http2.session.headers["X-Once"] == "yes"


def test_test_connection_returns_false_on_exception() -> None:
    """
    It returns (False, error) when the underlying request fails.
    """

    props = HttpLinkedServiceSettings(host="api.example.test", auth_type=AuthType.NO_AUTH)
    service = HttpLinkedService(id=uuid.uuid4(), name="test-name", version="1.0.0", settings=props)
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

    props = HttpLinkedServiceSettings(host="api.example.test", auth_type=AuthType.NO_AUTH)
    service = HttpLinkedService(id=uuid.uuid4(), name="test-name", version="1.0.0", settings=props)
    service._http = cast("Any", LinkedServiceHttp(session=type("S", (), {"headers": {}})()))
    ok, message = service.test_connection()
    assert ok is True
    assert "successfully" in message


def test_close_closes_underlying_http_client() -> None:
    """
    It closes the underlying Http client when _http is set.
    """
    props = HttpLinkedServiceSettings(host="api.example.test", auth_type=AuthType.NO_AUTH)
    service = HttpLinkedService(id=uuid.uuid4(), name="test-name", version="1.0.0", settings=props)
    fake_http = LinkedServiceHttp(session=type("S", (), {"headers": {}})())
    service._http = cast("Any", fake_http)
    service.close()
    assert fake_http.closed is True


def test_close_handles_missing_http_gracefully() -> None:
    """
    It does not raise when _http is None.
    """
    props = HttpLinkedServiceSettings(host="api.example.test", auth_type=AuthType.NO_AUTH)
    service = HttpLinkedService(id=uuid.uuid4(), name="test-name", version="1.0.0", settings=props)
    service._http = None
    service.close()  # Should not raise
