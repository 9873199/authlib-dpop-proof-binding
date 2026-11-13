"""Tests for the resource server side of DPoP (RFC 9449).

The proofs are signed in-process with freshly generated P-256 keys, and
the replay storage is a thread-safe in-memory fake. Nothing here opens a
network connection.
"""

import base64
import hashlib
import json
import logging
import runpy
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from joserfc import jws
from joserfc.jwk import ECKey

from authlib.oauth2.rfc6749 import MissingAuthorizationError
from authlib.oauth2.rfc6749 import OAuth2Request
from authlib.oauth2.rfc6749 import ResourceProtector
from authlib.oauth2.rfc6750 import BearerTokenValidator
from authlib.oauth2.rfc6750.errors import InsufficientScopeError
from authlib.oauth2.rfc6750.errors import InvalidTokenError
from authlib.oauth2.rfc9449 import DPoPProtection
from authlib.oauth2.rfc9449 import DPoPReplayStore
from authlib.oauth2.rfc9449 import DPoPTokenValidator
from authlib.oauth2.rfc9449 import InvalidDPoPProofError
from authlib.oauth2.rfc9449.validator import canonical_request_url
from authlib.oauth2.rfc9449.validator import compute_ath

RESOURCE_URL = "https://api.example.com/resource"
TOKEN_STRING = "access-token-secret-value"
OTHER_TOKEN_STRING = "another-access-token"


class FakeClock:
    """Injectable clock."""

    def __init__(self, now=1000.0):
        self.now = now

    def __call__(self):
        return self.now


class Token:
    """Minimal token model understood by BearerTokenValidator."""

    def __init__(self, access_token, jkt=None, expired=False, revoked=False, scope="profile"):
        self.access_token = access_token
        self.jkt = jkt
        self._expired = expired
        self._revoked = revoked
        self.scope = scope

    def is_expired(self):
        return self._expired

    def is_revoked(self):
        return self._revoked

    def get_scope(self):
        return self.scope


class InMemoryReplayStore(DPoPReplayStore):
    """Thread-safe check-and-insert, as a real database unique constraint."""

    def __init__(self):
        self._lock = threading.Lock()
        self.records = {}
        self.failing = False

    def register_proof_confirmation(self, jkt, jti, expires_at):
        with self._lock:
            if self.failing:
                raise RuntimeError("storage is unavailable")
            key = (jkt, jti)
            if key in self.records:
                return False
            self.records[key] = expires_at
            return True


class DPoPTestValidator(DPoPTokenValidator):
    def __init__(self, tokens, store, **kwargs):
        super().__init__(replay_store=store, **kwargs)
        self.tokens = tokens

    def authenticate_token(self, token_string):
        return self.tokens.get(token_string)

    def get_token_confirmation(self, token):
        if token is None:
            return None
        return token.jkt


class BearerTestValidator(BearerTokenValidator):
    def __init__(self, tokens):
        super().__init__()
        self.tokens = tokens

    def authenticate_token(self, token_string):
        return self.tokens.get(token_string)


def make_proof(
    key,
    token_string,
    method="GET",
    htu=RESOURCE_URL,
    iat=1000,
    jti="proof-jti",
    claims=None,
    header=None,
    alg="ES256",
):
    """Sign a real DPoP proof with the given EC private key."""
    protected = {"alg": alg, "typ": "dpop+jwt", "jwk": key.as_dict()}
    if header:
        protected.update(header)

    payload = {
        "jti": jti,
        "htm": method,
        "htu": htu,
        "iat": iat,
        "ath": compute_ath(token_string),
    }
    if claims:
        payload.update(claims)

    if alg == "ES256":
        return jws.serialize_compact(protected, json.dumps(payload), key)
    return jws.serialize_compact(
        protected, json.dumps(payload), key, algorithms=[alg]
    )


def make_request(proof, token_string, method="GET", uri=RESOURCE_URL, scheme="DPoP"):
    headers = {"Authorization": f"{scheme} {token_string}"}
    if proof is not None:
        headers["DPoP"] = proof
    return OAuth2Request(method, uri, headers=headers)


@pytest.fixture
def clock():
    return FakeClock()


@pytest.fixture
def store():
    return InMemoryReplayStore()


@pytest.fixture
def ec_key():
    return ECKey.generate_key("P-256", private=True)


@pytest.fixture
def other_key():
    return ECKey.generate_key("P-256", private=True)


@pytest.fixture
def tokens(ec_key):
    jkt = ec_key.thumbprint()
    return {
        TOKEN_STRING: Token(TOKEN_STRING, jkt=jkt),
        OTHER_TOKEN_STRING: Token(OTHER_TOKEN_STRING, jkt=jkt),
        "unbound-token": Token("unbound-token", jkt=None),
        "expired-token": Token("expired-token", jkt=jkt, expired=True),
        "revoked-token": Token("revoked-token", jkt=jkt, revoked=True),
        "scoped-token": Token("scoped-token", jkt=jkt, scope="profile"),
    }


@pytest.fixture
def protector(tokens, store, clock):
    protector = ResourceProtector()
    protector.register_token_validator(
        DPoPTestValidator(tokens, store, proof_max_age=60, clock_skew=10, clock=clock)
    )
    protector.register_extension(DPoPProtection())
    return protector


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


def test_valid_dpop_access(protector, store, ec_key, clock, tokens):
    proof = make_proof(ec_key, TOKEN_STRING, iat=int(clock.now))
    request = make_request(proof, TOKEN_STRING)

    token = protector.validate_request(None, request)

    assert token is tokens[TOKEN_STRING]
    assert len(store.records) == 1
    (jkt, jti), expires_at = next(iter(store.records.items()))
    assert jkt == ec_key.thumbprint()
    assert jti == "proof-jti"
    # The record covers the whole remaining acceptable window of the proof.
    assert expires_at == int(clock.now) + 60 + 10


def test_ath_is_sha256_base64url_without_padding():
    expected = base64.urlsafe_b64encode(
        hashlib.sha256(TOKEN_STRING.encode()).digest()
    ).rstrip(b"=").decode()
    assert compute_ath(TOKEN_STRING) == expected
    assert "=" not in compute_ath(TOKEN_STRING)


# ---------------------------------------------------------------------------
# Key binding
# ---------------------------------------------------------------------------


def test_wrong_key_is_rejected(protector, store, other_key, clock):
    proof = make_proof(other_key, TOKEN_STRING, iat=int(clock.now))
    request = make_request(proof, TOKEN_STRING)

    with pytest.raises(InvalidDPoPProofError):
        protector.validate_request(None, request)
    assert store.records == {}


def test_token_without_binding_rejects_matching_proof(protector, store, ec_key, clock):
    proof = make_proof(ec_key, "unbound-token", iat=int(clock.now))
    request = make_request(proof, "unbound-token")

    with pytest.raises(InvalidDPoPProofError):
        protector.validate_request(None, request)
    assert store.records == {}


def test_private_jwk_in_header_is_rejected(protector, store, ec_key, clock):
    proof = make_proof(
        ec_key,
        TOKEN_STRING,
        iat=int(clock.now),
        header={"jwk": ec_key.as_dict(private=True)},
    )
    request = make_request(proof, TOKEN_STRING)

    with pytest.raises(InvalidDPoPProofError):
        protector.validate_request(None, request)
    assert store.records == {}


def test_symmetric_and_none_algorithms_are_rejected(protector, store, clock):
    def b64url(data):
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    payload = b64url(
        json.dumps(
            {
                "jti": "j",
                "htm": "GET",
                "htu": RESOURCE_URL,
                "iat": int(clock.now),
                "ath": compute_ath(TOKEN_STRING),
            }
        ).encode()
    )
    for alg in ("none", "HS256"):
        header = b64url(json.dumps({"alg": alg, "typ": "dpop+jwt"}).encode())
        forged = f"{header}.{payload}."
        request = make_request(forged, TOKEN_STRING)
        with pytest.raises(InvalidDPoPProofError):
            protector.validate_request(None, request)
    assert store.records == {}


def test_p384_key_is_rejected(tokens, store, clock):
    protector = ResourceProtector()
    protector.register_token_validator(
        DPoPTestValidator(tokens, store, proof_max_age=60, clock_skew=10, clock=clock)
    )
    protector.register_extension(DPoPProtection())

    p384 = ECKey.generate_key("P-384", private=True)
    proof = make_proof(p384, TOKEN_STRING, iat=int(clock.now), alg="ES384")
    request = make_request(proof, TOKEN_STRING)

    with pytest.raises(InvalidDPoPProofError):
        protector.validate_request(None, request)


def test_jku_and_x5u_cannot_trigger_downloads(protector, store, ec_key, clock):
    for parameter in ("jku", "x5u"):
        proof = make_proof(
            ec_key,
            TOKEN_STRING,
            iat=int(clock.now),
            header={parameter: "https://attacker.example/keys"},
        )
        request = make_request(proof, TOKEN_STRING)
        with pytest.raises(InvalidDPoPProofError):
            protector.validate_request(None, request)
    assert store.records == {}


def test_typ_must_be_dpop_jwt(protector, store, ec_key, clock):
    proof = make_proof(
        ec_key, TOKEN_STRING, iat=int(clock.now), header={"typ": "JWT"}
    )
    request = make_request(proof, TOKEN_STRING)
    with pytest.raises(InvalidDPoPProofError):
        protector.validate_request(None, request)
    assert store.records == {}


def test_tampered_signature_is_rejected(protector, store, ec_key, clock):
    proof = make_proof(ec_key, TOKEN_STRING, iat=int(clock.now))
    tampered = proof[:-2] + ("AA" if not proof.endswith("AA") else "BB")
    request = make_request(tampered, TOKEN_STRING)
    with pytest.raises(InvalidDPoPProofError):
        protector.validate_request(None, request)
    assert store.records == {}


def test_malformed_proof_and_missing_header(protector, store, ec_key, clock):
    request = make_request("not-a-jwt", TOKEN_STRING)
    with pytest.raises(InvalidDPoPProofError):
        protector.validate_request(None, request)

    request = make_request(None, TOKEN_STRING)
    with pytest.raises(InvalidDPoPProofError):
        protector.validate_request(None, request)
    assert store.records == {}


# ---------------------------------------------------------------------------
# Request binding: htm and htu
# ---------------------------------------------------------------------------


def test_wrong_method_is_rejected(protector, store, ec_key, clock):
    proof = make_proof(ec_key, TOKEN_STRING, method="GET", iat=int(clock.now))
    request = make_request(proof, TOKEN_STRING, method="POST")

    with pytest.raises(InvalidDPoPProofError):
        protector.validate_request(None, request)
    assert store.records == {}


def test_wrong_url_is_rejected(protector, store, ec_key, clock):
    proof = make_proof(
        ec_key, TOKEN_STRING, htu="https://other.example.com/resource", iat=int(clock.now)
    )
    request = make_request(proof, TOKEN_STRING)

    with pytest.raises(InvalidDPoPProofError):
        protector.validate_request(None, request)
    assert store.records == {}


def test_htu_accepts_query_fragment_case_and_default_ports(
    protector, store, ec_key, clock, monkeypatch
):
    # Some canonicalization cases use plain http, which OAuth2Request only
    # accepts outside of production transports.
    monkeypatch.setenv("AUTHLIB_INSECURE_TRANSPORT", "1")
    iat = int(clock.now)
    cases = [
        (RESOURCE_URL, "GET", f"{RESOURCE_URL}?a=1&b=2#fragment"),
        ("HTTPS://API.EXAMPLE.COM/resource", "GET", RESOURCE_URL),
        ("https://api.example.com:443/resource", "GET", RESOURCE_URL),
        ("https://api.example.com/resource", "GET", "https://api.example.com:443/resource"),
        ("http://api.example.com:80/resource", "GET", "http://api.example.com/resource"),
    ]
    for index, (htu, method, uri) in enumerate(cases):
        proof = make_proof(
            ec_key, TOKEN_STRING, method=method, htu=htu, iat=iat, jti=f"j-{index}"
        )
        request = make_request(proof, TOKEN_STRING, method=method, uri=uri)
        assert protector.validate_request(None, request) is not None
    assert len(store.records) == len(cases)


def test_htu_keeps_escaped_bytes_and_path_case(protector, store, ec_key, clock):
    iat = int(clock.now)
    # percent-encoded bytes are not decoded
    proof = make_proof(ec_key, TOKEN_STRING, htu="https://api.example.com/a%2Fb", iat=iat)
    request = make_request(proof, TOKEN_STRING, uri="https://api.example.com/a%2Fb")
    protector.validate_request(None, request)

    # the same decoded path is a different URL
    proof = make_proof(ec_key, TOKEN_STRING, htu="https://api.example.com/a/b", iat=iat, jti="j2")
    request = make_request(proof, TOKEN_STRING, uri="https://api.example.com/a%2Fb")
    with pytest.raises(InvalidDPoPProofError):
        protector.validate_request(None, request)

    # path case is not folded
    proof = make_proof(ec_key, TOKEN_STRING, htu="https://api.example.com/Foo", iat=iat, jti="j3")
    request = make_request(proof, TOKEN_STRING, uri="https://api.example.com/foo")
    with pytest.raises(InvalidDPoPProofError):
        protector.validate_request(None, request)


def test_htu_non_default_port_matters(protector, ec_key, clock):
    proof = make_proof(
        ec_key, TOKEN_STRING, htu="https://api.example.com:8443/resource", iat=int(clock.now)
    )
    request = make_request(proof, TOKEN_STRING)
    with pytest.raises(InvalidDPoPProofError):
        protector.validate_request(None, request)


def test_canonical_request_url():
    base = ("https", "api.example.com", 443, "/resource")
    assert canonical_request_url("https://api.example.com/resource?x=1#f") == base
    assert canonical_request_url("HTTPS://API.Example.COM:443/resource") == base
    assert canonical_request_url("http://api.example.com/resource") == (
        "http",
        "api.example.com",
        80,
        "/resource",
    )
    assert canonical_request_url("https://api.example.com:8443/resource") == (
        "https",
        "api.example.com",
        8443,
        "/resource",
    )
    assert canonical_request_url("not a url") is None


# ---------------------------------------------------------------------------
# ath binding
# ---------------------------------------------------------------------------


def test_ath_must_match_the_presented_token(protector, store, ec_key, clock):
    # the proof was minted for another token string
    proof = make_proof(ec_key, OTHER_TOKEN_STRING, iat=int(clock.now))
    request = make_request(proof, TOKEN_STRING)

    with pytest.raises(InvalidDPoPProofError):
        protector.validate_request(None, request)
    assert store.records == {}


def test_ath_cannot_be_omitted(protector, store, ec_key, clock):
    proof = make_proof(ec_key, TOKEN_STRING, iat=int(clock.now), claims={"ath": ""})
    request = make_request(proof, TOKEN_STRING)
    with pytest.raises(InvalidDPoPProofError):
        protector.validate_request(None, request)
    assert store.records == {}


# ---------------------------------------------------------------------------
# jti and iat validation, time window
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "iat,accepted",
    [
        (1000, True),  # now
        (1010, True),  # exactly at the future skew boundary
        (930, True),  # exactly max_age + skew old
        (1011, False),  # too far in the future
        (929, False),  # too old
    ],
)
def test_proof_time_window(protector, store, ec_key, iat, accepted):
    proof = make_proof(ec_key, TOKEN_STRING, iat=iat, jti=f"jti-{iat}")
    request = make_request(proof, TOKEN_STRING)
    if accepted:
        protector.validate_request(None, request)
    else:
        with pytest.raises(InvalidDPoPProofError):
            protector.validate_request(None, request)


def test_iat_must_be_integer_not_boolean(protector, store, ec_key, clock):
    proof = make_proof(ec_key, TOKEN_STRING, iat=True, jti="bool-iat")
    request = make_request(proof, TOKEN_STRING)
    with pytest.raises(InvalidDPoPProofError):
        protector.validate_request(None, request)
    assert store.records == {}


@pytest.mark.parametrize("bad_jti", [None, "", 42, ["jti"]])
def test_jti_must_be_non_empty_string(protector, store, ec_key, clock, bad_jti):
    proof = make_proof(ec_key, TOKEN_STRING, iat=int(clock.now), jti=bad_jti)
    request = make_request(proof, TOKEN_STRING)
    with pytest.raises(InvalidDPoPProofError):
        protector.validate_request(None, request)
    assert store.records == {}


# ---------------------------------------------------------------------------
# Replay protection, concurrency and storage failures
# ---------------------------------------------------------------------------


def test_replay_is_rejected(protector, store, ec_key, clock):
    proof = make_proof(ec_key, TOKEN_STRING, iat=int(clock.now))

    protector.validate_request(None, make_request(proof, TOKEN_STRING))
    with pytest.raises(InvalidDPoPProofError):
        protector.validate_request(None, make_request(proof, TOKEN_STRING))

    assert len(store.records) == 1


def test_concurrent_replay_only_one_request_passes(protector, store, ec_key, clock):
    proof = make_proof(ec_key, TOKEN_STRING, iat=int(clock.now))
    barrier = threading.Barrier(8)

    def worker():
        barrier.wait()
        request = make_request(proof, TOKEN_STRING)
        try:
            protector.validate_request(None, request)
            return "accepted"
        except InvalidDPoPProofError:
            return "rejected"

    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(lambda _: worker(), range(8)))

    assert results.count("accepted") == 1
    assert results.count("rejected") == 7
    assert len(store.records) == 1


def test_storage_error_rejects_without_bearer_fallback(protector, store, ec_key, clock):
    store.failing = True
    proof = make_proof(ec_key, TOKEN_STRING, iat=int(clock.now))
    request = make_request(proof, TOKEN_STRING)

    with pytest.raises(InvalidDPoPProofError):
        protector.validate_request(None, request)
    assert store.records == {}


def test_failed_validation_does_not_consume_jti(protector, store, ec_key, other_key, clock):
    iat = int(clock.now)
    # a wrong-key proof fails before registration
    bad_proof = make_proof(other_key, TOKEN_STRING, iat=iat, jti="reused-jti")
    with pytest.raises(InvalidDPoPProofError):
        protector.validate_request(None, make_request(bad_proof, TOKEN_STRING))

    # the same jti in a valid proof is still accepted: failures leave no trace
    good_proof = make_proof(ec_key, TOKEN_STRING, iat=iat, jti="reused-jti")
    protector.validate_request(None, make_request(good_proof, TOKEN_STRING))
    assert len(store.records) == 1


# ---------------------------------------------------------------------------
# Token state and scopes keep their usual semantics
# ---------------------------------------------------------------------------


def test_revoked_expired_and_insufficient_scope_are_rejected(
    protector, store, ec_key, clock
):
    iat = int(clock.now)
    for token_string, error in [
        ("revoked-token", InvalidTokenError),
        ("expired-token", InvalidTokenError),
    ]:
        proof = make_proof(ec_key, token_string, iat=iat, jti=f"jti-{token_string}")
        with pytest.raises(error):
            protector.validate_request(None, make_request(proof, token_string))

    proof = make_proof(ec_key, "scoped-token", iat=iat, jti="jti-scope")
    request = make_request(proof, "scoped-token")
    with pytest.raises(InsufficientScopeError):
        protector.validate_request(["admin"], request)

    assert store.records == {}


def test_unknown_token_is_rejected(protector, store, ec_key, clock):
    proof = make_proof(ec_key, "unknown-token", iat=int(clock.now))
    request = make_request(proof, "unknown-token")
    with pytest.raises(InvalidTokenError):
        protector.validate_request(None, request)
    assert store.records == {}


# ---------------------------------------------------------------------------
# Bearer bypass and compatibility when DPoP is not enabled
# ---------------------------------------------------------------------------


def test_bound_token_cannot_bypass_with_bearer_scheme(tokens, store, ec_key, clock):
    protector = ResourceProtector()
    protector.register_token_validator(BearerTestValidator(tokens))
    protector.register_token_validator(
        DPoPTestValidator(tokens, store, proof_max_age=60, clock_skew=10, clock=clock)
    )
    protector.register_extension(DPoPProtection())

    request = OAuth2Request(
        "GET", RESOURCE_URL, headers={"Authorization": f"Bearer {TOKEN_STRING}"}
    )
    with pytest.raises(InvalidDPoPProofError):
        protector.validate_request(None, request)
    assert store.records == {}


def test_unbound_token_still_works_with_bearer_scheme(tokens, store, clock):
    protector = ResourceProtector()
    protector.register_token_validator(BearerTestValidator(tokens))
    protector.register_token_validator(
        DPoPTestValidator(tokens, store, proof_max_age=60, clock_skew=10, clock=clock)
    )
    protector.register_extension(DPoPProtection())

    request = OAuth2Request(
        "GET", RESOURCE_URL, headers={"Authorization": "Bearer unbound-token"}
    )
    token = protector.validate_request(None, request)
    assert token is tokens["unbound-token"]


def test_protector_without_extension_keeps_bearer_compatibility(tokens, ec_key):
    # No DPoPProtection: the bound token is accepted like any bearer token.
    protector = ResourceProtector()
    protector.register_token_validator(BearerTestValidator(tokens))

    request = OAuth2Request(
        "GET", RESOURCE_URL, headers={"Authorization": f"Bearer {TOKEN_STRING}"}
    )
    token = protector.validate_request(None, request)
    assert token is tokens[TOKEN_STRING]


def test_missing_and_unknown_authorization_schemes(protector):
    request = OAuth2Request("GET", RESOURCE_URL, headers={})
    with pytest.raises(MissingAuthorizationError) as exc_info:
        protector.validate_request(None, request)
    status, _, headers = exc_info.value()
    assert status == 401
    assert dict(headers)["WWW-Authenticate"] == "DPoP"

    request = OAuth2Request(
        "GET", RESOURCE_URL, headers={"Authorization": "Basic credentials"}
    )
    with pytest.raises(MissingAuthorizationError):
        protector.validate_request(None, request)


def test_composes_with_form_body_extension(tokens, store, ec_key, clock):
    from authlib.oauth2.rfc6750 import FormEncodedBodyToken

    class FormRequest(OAuth2Request):
        def __init__(self, method, headers, form):
            super().__init__(method, RESOURCE_URL, headers=headers)
            self._form = form

        @property
        def form(self):
            return self._form

    protector = ResourceProtector()
    protector.register_token_validator(BearerTestValidator(tokens))
    protector.register_token_validator(
        DPoPTestValidator(tokens, store, proof_max_age=60, clock_skew=10, clock=clock)
    )
    protector.register_extension(DPoPProtection())
    protector.register_extension(FormEncodedBodyToken())

    # The body token still works for an unbound token.
    request = FormRequest(
        "POST",
        {"Content-Type": "application/x-www-form-urlencoded"},
        {"access_token": "unbound-token"},
    )
    assert protector.validate_request(None, request) is tokens["unbound-token"]

    # A DPoP request on the header is still validated; no token in the body.
    proof = make_proof(ec_key, TOKEN_STRING, method="POST", iat=int(clock.now))
    request = FormRequest(
        "POST",
        {
            "Authorization": f"DPoP {TOKEN_STRING}",
            "DPoP": proof,
            "Content-Type": "application/x-www-form-urlencoded",
        },
        {},
    )
    assert protector.validate_request(None, request) is tokens[TOKEN_STRING]


# ---------------------------------------------------------------------------
# Error response and log hygiene
# ---------------------------------------------------------------------------


def test_error_carries_dpop_challenge(protector, ec_key, clock):
    proof = make_proof(ec_key, TOKEN_STRING, iat=int(clock.now) - 3600)
    request = make_request(proof, TOKEN_STRING)

    with pytest.raises(InvalidDPoPProofError) as exc_info:
        protector.validate_request(None, request)

    status, _, headers = exc_info.value()
    assert status == 401
    www_authenticate = dict(headers)["WWW-Authenticate"]
    assert www_authenticate.startswith("DPoP ")
    assert 'error="invalid_dpop_proof"' in www_authenticate


def test_errors_and_logs_never_contain_token_or_proof(
    protector, caplog, ec_key, other_key, clock
):
    proof = make_proof(other_key, TOKEN_STRING, iat=int(clock.now))
    request = make_request(proof, TOKEN_STRING)

    caplog.set_level(logging.WARNING)
    with pytest.raises(InvalidDPoPProofError) as exc_info:
        protector.validate_request(None, request)

    status, body, _ = exc_info.value()
    assert status == 401
    rendered = json.dumps(body) + caplog.text
    assert TOKEN_STRING not in rendered
    assert proof not in rendered


# ---------------------------------------------------------------------------
# Runnable integration example
# ---------------------------------------------------------------------------


def test_example_runs_end_to_end(capfd):
    example = (
        Path(__file__).resolve().parents[3]
        / "examples"
        / "dpop_resource_server.py"
    )
    runpy.run_path(str(example), run_name="__main__")
    output = capfd.readouterr().out

    assert "legitimate DPoP request" in output
    assert "ACCEPTED 200" in output
    assert "same proof replayed" in output
    assert "cannot bypass the proof check" in output
    assert "no Bearer downgrade" in output
    # The token value and raw proofs never leak into the visible output.
    assert "issued-access-token" not in output
    assert "eyJ" not in output  # start of a base64url JWT segment
