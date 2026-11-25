"""End-to-end PAR (RFC 9126) tests with an in-process local client.

No external OAuth service and no sockets are used. The harness drives the real
``AuthorizationServer`` entry points, the real ``AuthorizationCodeGrant`` and
the RFC 7636 PKCE extension, with a thread-safe in-memory PAR storage.
"""

import base64
import logging
import threading
from collections import defaultdict
from urllib.parse import parse_qs
from urllib.parse import urlencode
from urllib.parse import urlparse

import pytest

from authlib.common.security import generate_token
from authlib.oauth2.base import OAuth2Error
from authlib.oauth2.rfc6749 import AuthorizationServer
from authlib.oauth2.rfc6749 import ClientMixin
from authlib.oauth2.rfc6749 import OAuth2Request
from authlib.oauth2.rfc6749.grants import AuthorizationCodeGrant
from authlib.oauth2.rfc6749.requests import OAuth2Payload
from authlib.oauth2.rfc6749.util import list_to_scope
from authlib.oauth2.rfc6749.util import normalize_response_type
from authlib.oauth2.rfc6749.util import scope_to_list
from authlib.oauth2.rfc7636 import CodeChallenge
from authlib.oauth2.rfc7636 import create_s256_code_challenge
from authlib.oauth2.rfc9126 import STATUS_ACTIVE
from authlib.oauth2.rfc9126 import STATUS_CONSUMED
from authlib.oauth2.rfc9126 import STATUS_FAILED
from authlib.oauth2.rfc9126 import InvalidRequestUriError
from authlib.oauth2.rfc9126 import MemoryPushedAuthorizationStorage
from authlib.oauth2.rfc9126 import PushedAuthorizationClientMismatch
from authlib.oauth2.rfc9126 import PushedAuthorizationConflict
from authlib.oauth2.rfc9126 import PushedAuthorizationRequests
from authlib.oauth2.rfc9126 import digest_handle
from authlib.oauth2.rfc9126 import handle_from_request_uri

CLIENT_ID = "client-id"
OTHER_CLIENT_ID = "other-client"
CLIENT_SECRET = "client-secret"
REDIRECT_URI = "https://client.example.com/cb"
SCOPE = "profile address"
ISSUER = "https://as.example.com"


class User:
    def __init__(self, user_id=1):
        self.id = user_id

    def get_user_id(self):
        return self.id


class TestClient(ClientMixin):
    __test__ = False

    def __init__(
        self,
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
        auth_method="client_secret_basic",
        redirect_uris=(REDIRECT_URI,),
        scopes=("profile", "address"),
    ):
        self.client_id = client_id
        self.client_secret = client_secret
        self.auth_method = auth_method
        self.redirect_uris = list(redirect_uris)
        self.scopes = list(scopes)
        self.response_types = ["code"]
        self.grant_types = ["authorization_code"]

    def get_client_id(self):
        return self.client_id

    def get_default_redirect_uri(self):
        return self.redirect_uris[0]

    def get_allowed_scope(self, scope):
        allowed = set(self.scopes)
        if not scope:
            return list_to_scope(sorted(allowed))
        return list_to_scope([name for name in scope_to_list(scope) if name in allowed])

    def check_redirect_uri(self, redirect_uri):
        # Exact matching only, per RFC 9126 §2.4 / OAuth security BCP.
        return redirect_uri in self.redirect_uris

    def check_client_secret(self, client_secret):
        return client_secret == self.client_secret

    def check_endpoint_auth_method(self, method, endpoint):
        if endpoint in {"token", "pushed_authorization"}:
            return method == self.auth_method
        return False

    def check_response_type(self, response_type):
        return normalize_response_type(response_type) in {
            normalize_response_type(value) for value in self.response_types
        }

    def check_grant_type(self, grant_type):
        return grant_type in self.grant_types


class StoredCode:
    def __init__(self, **values):
        self.__dict__.update(values)

    def get_redirect_uri(self):
        return self.redirect_uri

    def get_scope(self):
        return self.scope


class CodeGrant(AuthorizationCodeGrant):
    def save_authorization_code(self, code, request):
        if self.server.fail_code_save:
            raise RuntimeError("code storage is unavailable")
        authorization_code = StoredCode(
            code=code,
            client_id=request.client.client_id,
            redirect_uri=request.payload.redirect_uri,
            scope=request.scope,
            user_id=request.user.id,
            code_challenge=request.payload.data.get("code_challenge"),
            code_challenge_method=request.payload.data.get("code_challenge_method"),
        )
        self.server.codes[code] = authorization_code
        self.server.issue_count += 1
        return authorization_code

    def query_authorization_code(self, code, client):
        authorization_code = self.server.codes.get(code)
        if authorization_code and authorization_code.client_id == client.client_id:
            return authorization_code
        return None

    def delete_authorization_code(self, authorization_code):
        self.server.codes.pop(authorization_code.code, None)

    def authenticate_user(self, authorization_code):
        return self.server.users.get(authorization_code.user_id)


class LocalPayload(OAuth2Payload):
    def __init__(self, pairs):
        self._datalist = defaultdict(list)
        self._data = {}
        for name, value in pairs:
            self._datalist[name].append(value)
            self._data.setdefault(name, value)

    @property
    def data(self):
        return self._data

    @property
    def datalist(self):
        return self._datalist


def _as_pairs(data):
    if data is None:
        return []
    if isinstance(data, (list, tuple)):
        pairs = []
        for item in data:
            pairs.append((item[0], item[1]))
        return pairs
    pairs = []
    for name, value in data.items():
        if isinstance(value, (list, tuple)):
            for item in value:
                pairs.append((name, item))
        else:
            pairs.append((name, value))
    return pairs


class LocalRequest(OAuth2Request):
    def __init__(self, method, path, *, query=None, form=None, headers=None):
        query_pairs = _as_pairs(query)
        url = ISSUER + path
        if query_pairs:
            url += "?" + urlencode(query_pairs)
        super().__init__(method, url, headers=headers or {})

        form_pairs = _as_pairs(form)
        # request.values merges query and form parameters.
        self.payload = LocalPayload(query_pairs + form_pairs)
        self._form = dict(form_pairs)

    @property
    def form(self):
        return self._form


class LocalResponse:
    def __init__(self, status_code, body, headers):
        self.status_code = status_code
        self.body = body
        self.headers = list(headers)

    def header(self, name):
        for key, value in self.headers:
            if key.lower() == name.lower():
                return value
        return None

    @property
    def location(self):
        return self.header("Location")

    def query(self):
        parsed = urlparse(self.location)
        return {key: values[0] for key, values in parse_qs(parsed.query).items()}


class LocalAuthorizationServer(AuthorizationServer):
    def __init__(self, storage, **par_kwargs):
        super().__init__()
        self.storage = storage
        self.clients = {}
        self.users = {1: User(1)}
        self.codes = {}
        self.tokens = []
        self.issue_count = 0
        self.fail_code_save = False

        self.register_token_generator(
            "default",
            lambda **kwargs: {
                "access_token": generate_token(32),
                "token_type": "Bearer",
                "expires_in": 3600,
            },
        )
        self.par = PushedAuthorizationRequests(storage, **par_kwargs)
        self.register_extension(self.par)
        self.register_grant(
            CodeGrant,
            [self.par.grant_extension, CodeChallenge()],
        )

    def add_client(self, client):
        self.clients[client.client_id] = client
        return client

    def query_client(self, client_id):
        return self.clients.get(client_id)

    def save_token(self, token, request):
        self.tokens.append(token)

    def send_signal(self, name, *args, **kwargs):
        return None

    def create_oauth2_request(self, request):
        return request

    def handle_response(self, status, body, headers):
        return LocalResponse(status, body, headers)


def basic_header(client_id=CLIENT_ID, client_secret=CLIENT_SECRET):
    raw = f"{client_id}:{client_secret}".encode()
    token = base64.b64encode(raw).decode()
    return {"Authorization": "Basic " + token}


class ParLocalClient:
    """A tiny in-process client: authenticated pusher + browser round trips."""

    def __init__(self, server, client_id=CLIENT_ID):
        self.server = server
        self.client_id = client_id

    def push(
        self,
        params=None,
        *,
        auth_header=True,
        client_secret=CLIENT_SECRET,
        client_id=None,
    ):
        body = {
            "response_type": "code",
            "client_id": client_id or self.client_id,
            "redirect_uri": REDIRECT_URI,
            "scope": SCOPE,
            "state": "state-xyz",
        }
        if params:
            body.update(params)
        headers = (
            basic_header(client_id or self.client_id, client_secret)
            if auth_header
            else {}
        )
        request = LocalRequest("POST", "/oauth/par", form=body, headers=headers)
        return self.server.create_endpoint_response("pushed_authorization", request)

    def _reference(self, request_uri, extra=None, client_id=None):
        query = [
            ("client_id", client_id or self.client_id),
            ("request_uri", request_uri),
        ]
        if extra:
            query.extend(_as_pairs(extra))
        return query

    def open_authorize(self, request_uri, *, user=None, extra=None, client_id=None):
        """Simulate a browser GET of the consent page. Never consumes."""
        request = LocalRequest(
            "GET",
            "/oauth/authorize",
            query=self._reference(request_uri, extra, client_id=client_id),
        )
        try:
            grant = self.server.get_consent_grant(request, end_user=user)
            return grant
        except OAuth2Error as error:
            return self.server.handle_error_response(request, error)

    def decide(
        self,
        request_uri,
        *,
        approved=True,
        user=None,
        extra=None,
        client_id=None,
    ):
        user = user or self.server.users[1]
        query = self._reference(request_uri, extra=extra, client_id=client_id)
        form = [("user_id", str(user.id)), ("decision", "allow")]
        request = LocalRequest("POST", "/oauth/authorize", query=query, form=form)
        try:
            grant = self.server.get_consent_grant(request, end_user=user)
        except OAuth2Error as error:
            return self.server.handle_error_response(request, error)

        grant_user = user if approved else None
        return self.server.create_authorization_response(
            request, grant_user=grant_user, grant=grant
        )

    def exchange_code(self, code, *, code_verifier=None, redirect_uri=REDIRECT_URI):
        form = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
        }
        if code_verifier:
            form["code_verifier"] = code_verifier
        request = LocalRequest(
            "POST",
            "/oauth/token",
            form=form,
            headers=basic_header(),
        )
        return self.server.create_token_response(request)


@pytest.fixture
def clock():
    return {"now": 1_000_000.0}


@pytest.fixture
def storage(clock):
    return MemoryPushedAuthorizationStorage(time_func=lambda: clock["now"])


@pytest.fixture
def server(storage):
    authorization_server = LocalAuthorizationServer(storage, expires_in=60)
    authorization_server.add_client(TestClient())
    authorization_server.add_client(TestClient(client_id=OTHER_CLIENT_ID))
    return authorization_server


@pytest.fixture
def local(server):
    return ParLocalClient(server)


def pushed_uri(response):
    assert response.status_code == 201, response.body
    return response.body["request_uri"]


def record_for(storage, request_uri):
    return storage.get(handle_from_request_uri(request_uri))


def test_par_happy_path_pkce_browser_roundtrip_and_token(server, local, storage):
    code_verifier = generate_token(64)
    code_challenge = create_s256_code_challenge(code_verifier)

    response = local.push(
        {
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }
    )
    request_uri = pushed_uri(response)
    assert request_uri.startswith("urn:ietf:params:oauth:request_uri:")
    assert response.body["expires_in"] == 60

    handle = handle_from_request_uri(request_uri)
    record = storage.get(handle)
    assert record.status == STATUS_ACTIVE
    assert record.client_id == CLIENT_ID
    assert record.version
    assert record.expires_at > storage.now()
    # Frozen parameters carry the validated PKCE material and exact redirect.
    assert record.params["code_challenge"] == [code_challenge]
    assert record.params["redirect_uri"] == [REDIRECT_URI]

    # Opening and refreshing the consent page does not consume the handle.
    anonymous_grant = local.open_authorize(request_uri)
    assert anonymous_grant.prompt == "login"
    assert local.open_authorize(request_uri).prompt == "login"
    assert storage.get(handle).status == STATUS_ACTIVE

    response = local.decide(request_uri, approved=True)
    assert response.status_code == 303
    params = response.query()
    assert "code" in params
    assert params["state"] == "state-xyz"
    assert server.issue_count == 1
    assert storage.get(handle).status == STATUS_CONSUMED

    token_response = local.exchange_code(params["code"], code_verifier=code_verifier)
    assert token_response.status_code == 200
    assert token_response.body["access_token"]
    assert server.tokens


def test_legacy_authorization_code_flow_still_works(server):
    request = LocalRequest(
        "GET",
        "/oauth/authorize",
        query=[
            ("response_type", "code"),
            ("client_id", CLIENT_ID),
            ("redirect_uri", REDIRECT_URI),
            ("state", "legacy"),
        ],
    )
    user = server.users[1]
    grant = server.get_consent_grant(request, end_user=user)
    response = server.create_authorization_response(
        request, grant_user=user, grant=grant
    )
    assert response.status_code == 303
    code = response.query()["code"]
    assert server.issue_count == 1

    token_response = ParLocalClient(server).exchange_code(code)
    assert token_response.status_code == 200
    assert token_response.body["access_token"]


@pytest.mark.parametrize(
    "extra",
    [
        [("scope", "profile")],
        [("redirect_uri", "https://evil.example/cb")],
        [("code_challenge", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")],
        [("code_challenge_method", "S256")],
        [("response_type", "token")],
        [("state", "tampered")],
    ],
)
def test_frontchannel_parameter_override_is_rejected(local, storage, extra):
    request_uri = pushed_uri(local.push())
    handle = handle_from_request_uri(request_uri)

    result = local.open_authorize(request_uri, user=None, extra=extra)
    assert isinstance(result, LocalResponse)
    assert result.status_code == 400
    assert result.body["error"] == "invalid_request"
    # Nothing was assembled and the handle stays usable.
    assert storage.get(handle).status == STATUS_ACTIVE

    # The legitimate frozen request still completes exactly once.
    response = local.decide(request_uri)
    assert response.status_code == 303


def test_repeated_frontchannel_parameter_is_rejected(local):
    request_uri = pushed_uri(local.push())
    result = local.open_authorize(
        request_uri,
        extra=[("scope", "profile"), ("scope", "address")],
    )
    assert isinstance(result, LocalResponse)
    assert result.status_code == 400
    assert result.body["error"] == "invalid_request"


def test_handle_cannot_be_used_by_another_client(local, storage, server):
    request_uri = pushed_uri(local.push())
    handle = handle_from_request_uri(request_uri)

    result = local.open_authorize(request_uri, client_id=OTHER_CLIENT_ID)
    assert isinstance(result, LocalResponse)
    assert result.status_code == 400
    assert result.body["error"] == "invalid_request_uri"
    assert storage.get(handle).status == STATUS_ACTIVE

    result = local.decide(request_uri, client_id=OTHER_CLIENT_ID)
    assert result.status_code == 400
    assert result.body["error"] == "invalid_request_uri"
    assert server.issue_count == 0

    with pytest.raises(PushedAuthorizationClientMismatch):
        storage.consume(
            handle,
            client_id=OTHER_CLIENT_ID,
            version=storage.get(handle).version,
            decision="approved",
        )


def test_unknown_request_uri_is_rejected(local):
    result = local.open_authorize("urn:ietf:params:oauth:request_uri:does-not-exist")
    assert isinstance(result, LocalResponse)
    assert result.status_code == 400
    assert result.body["error"] == "invalid_request_uri"


def test_push_rejects_request_uri_parameter(local):
    response = local.push({"request_uri": "urn:ietf:params:oauth:request_uri:abc"})
    assert response.status_code == 400
    assert response.body["error"] == "invalid_request"


def test_push_requires_client_authentication(local):
    response = local.push(auth_header=False)
    assert response.status_code == 401
    assert response.body["error"] == "invalid_client"


def test_push_rejects_unregistered_redirect_uri_as_json(local):
    response = local.push({"redirect_uri": "https://evil.example/cb"})
    assert response.status_code == 400
    assert response.body["error"] == "invalid_request"
    # PAR errors are never redirects.
    assert response.location is None


def test_push_rejects_malformed_pkce_challenge(local):
    response = local.push({"code_challenge": "too-short"})
    assert response.status_code == 400
    assert response.body["error"] == "invalid_request"


def test_expiry_boundary(local, storage, clock, server):
    request_uri = pushed_uri(local.push())
    handle = handle_from_request_uri(request_uri)
    expires_at = storage.get(handle).expires_at

    # One instant before the boundary it still renders.
    clock["now"] = expires_at - 1e-6
    grant = local.open_authorize(request_uri, user=server.users[1])
    assert not isinstance(grant, LocalResponse)

    # At the boundary it is invalid, deterministically, on page load...
    clock["now"] = expires_at
    result = local.open_authorize(request_uri)
    assert isinstance(result, LocalResponse)
    assert result.body["error"] == "invalid_request_uri"

    # ...and a late confirmation cannot issue a code.
    result = local.decide(request_uri)
    assert result.status_code == 400
    assert result.body["error"] == "invalid_request_uri"
    assert server.issue_count == 0


def test_consumed_handle_cannot_be_replayed_or_reactivated(local, storage, server):
    request_uri = pushed_uri(local.push())
    handle = handle_from_request_uri(request_uri)
    version_before = storage.get(handle).version

    response = local.decide(request_uri)
    assert response.status_code == 303

    # Browser back/refresh/late POST: deterministic rejection.
    result = local.open_authorize(request_uri)
    assert isinstance(result, LocalResponse)
    assert result.body["error"] == "invalid_request_uri"
    result = local.decide(request_uri)
    assert result.status_code == 400
    assert result.body["error"] == "invalid_request_uri"
    assert server.issue_count == 1

    # Stale version compare-and-set can never overwrite the terminal state.
    with pytest.raises(PushedAuthorizationConflict):
        storage.consume(
            handle,
            client_id=CLIENT_ID,
            version=version_before,
            decision="approved",
        )


class BarrierStorage(MemoryPushedAuthorizationStorage):
    def __init__(self, parties, **kwargs):
        super().__init__(**kwargs)
        self.barrier = threading.Barrier(parties, timeout=10)

    def consume(self, *args, **kwargs):
        # Line both threads up immediately before the atomic compare-and-set.
        self.barrier.wait()
        return super().consume(*args, **kwargs)


def test_two_concurrent_approvals_issue_exactly_one_code(clock):
    storage = BarrierStorage(2, time_func=lambda: clock["now"])
    server = LocalAuthorizationServer(storage, expires_in=60)
    server.add_client(TestClient())
    local = ParLocalClient(server)

    request_uri = pushed_uri(local.push())

    outcomes = []
    errors = []

    def confirm():
        try:
            outcomes.append(local.decide(request_uri, approved=True))
        except BaseException as error:  # surface unexpected thread failures
            errors.append(error)

    threads = [threading.Thread(target=confirm) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)

    assert not errors, errors
    assert len(outcomes) == 2
    redirects = [r for r in outcomes if r.status_code == 303]
    rejected = [
        r
        for r in outcomes
        if r.status_code == 400 and r.body["error"] == "invalid_request_uri"
    ]
    assert len(redirects) == 1
    assert len(rejected) == 1
    assert server.issue_count == 1
    assert len(server.codes) == 1
    assert storage.get(handle_from_request_uri(request_uri)).status == STATUS_CONSUMED


def test_storage_outage_during_consume_is_recoverable(clock):
    class FlakyStorage(MemoryPushedAuthorizationStorage):
        def __init__(self, **kwargs):
            super().__init__(**kwargs)
            self.fail_next_consume = True

        def consume(self, *args, **kwargs):
            if self.fail_next_consume:
                self.fail_next_consume = False
                raise RuntimeError("transient database outage")
            return super().consume(*args, **kwargs)

    storage = FlakyStorage(time_func=lambda: clock["now"])
    server = LocalAuthorizationServer(storage, expires_in=60)
    server.add_client(TestClient())
    local = ParLocalClient(server)
    request_uri = pushed_uri(local.push())
    handle = handle_from_request_uri(request_uri)
    version = storage.get(handle).version

    response = local.decide(request_uri)
    assert response.status_code == 500
    assert response.body["error"] == "server_error"
    # The claim never happened: the same handle/version can be retried.
    record = storage.get(handle)
    assert record.status == STATUS_ACTIVE
    assert record.version == version

    response = local.decide(request_uri)
    assert response.status_code == 303
    assert server.issue_count == 1


def test_issuance_failure_marks_handle_failed_and_is_terminal(local, server, storage):
    request_uri = pushed_uri(local.push())
    handle = handle_from_request_uri(request_uri)
    server.fail_code_save = True

    response = local.decide(request_uri)
    assert response.status_code == 500
    assert response.body["error"] == "server_error"
    assert server.issue_count == 0
    assert storage.get(handle).status == STATUS_FAILED

    # A retry is deterministically rejected; the old handle cannot be replayed.
    response = local.decide(request_uri)
    assert response.status_code == 400
    assert response.body["error"] == "invalid_request_uri"
    assert server.issue_count == 0


def test_denial_consumes_handle_as_terminal(local, server, storage):
    request_uri = pushed_uri(local.push())
    handle = handle_from_request_uri(request_uri)

    response = local.decide(request_uri, approved=False)
    assert response.status_code == 303
    assert "error=access_denied" in response.location
    assert server.issue_count == 0
    record = storage.get(handle)
    assert record.status == STATUS_CONSUMED
    assert record.decision == "denied"

    response = local.decide(request_uri, approved=False)
    assert response.status_code == 400
    assert response.body["error"] == "invalid_request_uri"


def test_storage_version_cas_contract(storage):
    first = storage.create(
        client_id=CLIENT_ID,
        params={"response_type": ["code"]},
        expires_in=60,
    )
    second = storage.create(
        client_id=CLIENT_ID,
        params={"response_type": ["code"]},
        expires_in=60,
    )
    assert first.handle != second.handle
    assert first.version != second.version

    consumed = storage.consume(
        first.handle,
        client_id=CLIENT_ID,
        version=first.version,
        decision="approved",
    )
    assert consumed.status == STATUS_CONSUMED
    assert consumed.version != first.version

    with pytest.raises(PushedAuthorizationConflict):
        storage.consume(
            first.handle,
            client_id=CLIENT_ID,
            version=first.version,
            decision="approved",
        )


def test_logs_only_handle_digest(local, storage, caplog):
    request_uri = pushed_uri(local.push())
    handle = handle_from_request_uri(request_uri)

    caplog.set_level(logging.DEBUG, logger="authlib.oauth2.rfc9126")
    local.decide(request_uri)

    par_records = [
        record
        for record in caplog.records
        if record.name.startswith("authlib.oauth2.rfc9126")
    ]
    text = " ".join(record.getMessage() for record in par_records)
    assert handle not in text
    assert request_uri not in text
    assert digest_handle(handle) in text


def test_invalid_request_uri_error_is_oauth2_error():
    error = InvalidRequestUriError()
    assert error.error == "invalid_request_uri"
    assert error.status_code == 400
