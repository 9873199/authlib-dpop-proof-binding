"""Framework-level PAR smoke test with the Flask test client.

The concurrency and expiration-boundary assertions live in the framework-free
``tests/core/test_oauth2/test_rfc9126.py`` harness. This module only proves
that the endpoint/extension wiring works with real Flask requests.
"""

import base64

import pytest

from authlib.oauth2.rfc6749.grants import (
    AuthorizationCodeGrant as _AuthorizationCodeGrant,
)
from authlib.oauth2.rfc7636 import CodeChallenge
from authlib.oauth2.rfc9126 import STATUS_CONSUMED
from authlib.oauth2.rfc9126 import MemoryPushedAuthorizationStorage
from authlib.oauth2.rfc9126 import PushedAuthorizationRequests
from authlib.oauth2.rfc9126 import handle_from_request_uri

from .models import CodeGrantMixin
from .models import save_authorization_code


class AuthorizationCodeGrant(CodeGrantMixin, _AuthorizationCodeGrant):
    TOKEN_ENDPOINT_AUTH_METHODS = [
        "client_secret_basic",
        "client_secret_post",
        "none",
    ]

    def save_authorization_code(self, code, request):
        return save_authorization_code(code, request)


@pytest.fixture
def par_storage():
    return MemoryPushedAuthorizationStorage()


@pytest.fixture
def par_server(app, server, par_storage):
    # Use the end_user code path instead of the cookie authorization session.
    app.config["AUTHORIZATION_SESSION"] = None
    par = PushedAuthorizationRequests(par_storage, expires_in=60)
    server.register_extension(par)
    server.register_grant(
        AuthorizationCodeGrant,
        [par.grant_extension, CodeChallenge()],
    )

    @app.route("/oauth/par", methods=["POST"])
    def pushed_authorization_endpoint():
        return server.create_endpoint_response("pushed_authorization")

    return server


def basic_header(client_id, client_secret):
    token = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()
    return {"Authorization": "Basic " + token}


def test_flask_par_push_browser_roundtrip(
    app, client, test_client, par_server, par_storage
):
    push_response = test_client.post(
        "/oauth/par",
        data={
            "response_type": "code",
            "client_id": "client-id",
            "redirect_uri": "https://client.test/authorized",
            "scope": "profile",
            "state": "abc",
        },
        headers=basic_header("client-id", "client-secret"),
    )
    assert push_response.status_code == 201
    payload = push_response.get_json()
    request_uri = payload["request_uri"]
    assert payload["expires_in"] == 60

    # Anonymous browser hit renders the login interaction, without consuming.
    page = test_client.get(
        "/oauth/authorize",
        query_string={
            "client_id": "client-id",
            "request_uri": request_uri,
        },
    )
    assert page.data == b"login"
    handle = handle_from_request_uri(request_uri)
    assert par_storage.get(handle).status == "active"

    # Final decision commits and issues exactly one code.
    decision = test_client.post(
        "/oauth/authorize",
        query_string={
            "client_id": "client-id",
            "request_uri": request_uri,
        },
        data={"user_id": "1"},
    )
    assert decision.status_code == 303
    assert "code=" in decision.location
    assert par_storage.get(handle).status == STATUS_CONSUMED

    # Reusing the handle is rejected.
    replay = test_client.post(
        "/oauth/authorize",
        query_string={
            "client_id": "client-id",
            "request_uri": request_uri,
        },
        data={"user_id": "1"},
    )
    assert replay.status_code == 400
    assert b"invalid_request_uri" in replay.data


def test_flask_par_rejects_frontchannel_scope_override(client, test_client, par_server):
    push_response = test_client.post(
        "/oauth/par",
        data={
            "response_type": "code",
            "client_id": "client-id",
            "redirect_uri": "https://client.test/authorized",
            "scope": "profile",
        },
        headers=basic_header("client-id", "client-secret"),
    )
    request_uri = push_response.get_json()["request_uri"]

    response = test_client.get(
        "/oauth/authorize",
        query_string=[
            ("client_id", "client-id"),
            ("request_uri", request_uri),
            ("scope", "profile"),
        ],
    )
    assert response.status_code == 400
    assert response.get_json()["error"] == "invalid_request"
