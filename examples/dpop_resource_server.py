"""Runnable DPoP resource server example (RFC 9449).

Run it from the repository root with::

    python examples/dpop_resource_server.py

It uses only the Authlib core, joserfc and the standard library. No web
framework, socket or external service is involved: the HTTP layer is
simulated with :class:`authlib.oauth2.rfc6749.OAuth2Request`.

The example shows the two callbacks a resource server has to provide:

1. ``get_token_confirmation`` reads the ``cnf.jkt`` confirmation bound to
   an already issued access token.
2. ``register_proof_confirmation`` atomically records a used proof. The
   check-and-insert MUST be a single atomic database operation (unique
   constraint / ``SET NX`` / ``INSERT ... ON CONFLICT``). When it raises,
   the request is rejected: the resource server never downgrades to plain
   Bearer validation.
"""

import hashlib
import json
import logging
import threading
import time

from joserfc import jws
from joserfc.jwk import ECKey

from authlib.common.encoding import to_bytes
from authlib.common.encoding import to_unicode
from authlib.common.encoding import urlsafe_b64encode
from authlib.oauth2.rfc6749 import OAuth2Request
from authlib.oauth2.rfc6749 import ResourceProtector
from authlib.oauth2.rfc6750 import BearerTokenValidator
from authlib.oauth2.rfc9449 import DPoPProtection
from authlib.oauth2.rfc9449 import DPoPReplayStore
from authlib.oauth2.rfc9449 import DPoPTokenValidator
from authlib.oauth2.rfc9449 import InvalidDPoPProofError

RESOURCE_URL = "https://api.example.com/resource"
ACCESS_TOKEN = "issued-access-token"


def ath_for(token_string):
    """The ath claim: base64url(SHA-256(token)) without padding."""
    digest = hashlib.sha256(to_bytes(token_string)).digest()
    return to_unicode(urlsafe_b64encode(digest))


class Token:
    """A token row as the authorization server would have issued it."""

    def __init__(self, access_token, jkt, scope="profile"):
        self.access_token = access_token
        # The confirmation claim stored on the token: {"cnf": {"jkt": ...}}.
        self.jkt = jkt
        self.scope = scope

    def is_expired(self):
        return False

    def is_revoked(self):
        return False

    def get_scope(self):
        return self.scope


class DatabaseReplayStore(DPoPReplayStore):
    """In-memory stand-in for the replay table of a real database.

    A production implementation runs the check-and-insert in one atomic
    statement, for example with a unique constraint on ``(jkt, jti)``::

        INSERT INTO dpop_nonce (jkt, jti, expires_at)
        VALUES (:jkt, :jti, :expires_at)
        ON CONFLICT (jkt, jti) DO NOTHING
        -- then inspect the row count: 1 = first use, 0 = replay

    The ``expires_at`` value covers the remaining acceptable lifetime of
    the proof, so a background job can safely delete expired rows.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._rows = {}
        self.simulated_outage = False

    def register_proof_confirmation(self, jkt, jti, expires_at):
        with self._lock:  # the atomicity a unique constraint would provide
            if self.simulated_outage:
                raise RuntimeError("database unavailable")
            key = (jkt, jti)
            if key in self._rows:
                return False  # the proof was already recorded: replay
            self._rows[key] = expires_at
            return True  # first registration, the request may proceed


class ExampleDPoPValidator(DPoPTokenValidator):
    def __init__(self, tokens, replay_store):
        super().__init__(replay_store=replay_store, proof_max_age=60, clock_skew=5)
        self._tokens = tokens

    def authenticate_token(self, token_string):
        # The usual token lookup, unchanged from a Bearer deployment.
        return self._tokens.get(token_string)

    def get_token_confirmation(self, token):
        # Callback 1: read cnf.jkt from the token object.
        return token.jkt if token is not None else None


class ExampleBearerValidator(BearerTokenValidator):
    """Keeps accepting legacy tokens that have no cnf.jkt binding."""

    def __init__(self, tokens):
        super().__init__()
        self._tokens = tokens

    def authenticate_token(self, token_string):
        return self._tokens.get(token_string)


def build_protector(tokens, replay_store):
    protector = ResourceProtector()
    protector.register_token_validator(ExampleBearerValidator(tokens))
    protector.register_token_validator(ExampleDPoPValidator(tokens, replay_store))
    protector.register_extension(DPoPProtection())
    return protector


def sign_dpop_proof(private_key, token_string, method, htu, jti, iat):
    """Mint a real DPoP proof with a freshly generated P-256 key."""
    protected = {
        "alg": "ES256",
        "typ": "dpop+jwt",
        "jwk": private_key.as_dict(),  # public EC JWK, no private fields
    }
    claims = {
        "jti": jti,
        "iat": iat,
        "htm": method,
        "htu": htu,
        "ath": ath_for(token_string),
    }
    return jws.serialize_compact(protected, json.dumps(claims), private_key)


def call_resource(protector, proof, token_string, method="GET", uri=RESOURCE_URL):
    """Simulate an API call and report whether the resource accepted it."""
    headers = {"Authorization": f"DPoP {token_string}", "DPoP": proof}
    request = OAuth2Request(method, uri, headers=headers)
    try:
        protector.validate_request(None, request)
    except InvalidDPoPProofError as error:
        status, _, headers = error()
        challenge = dict(headers)["WWW-Authenticate"]
        return f"REJECTED {status} ({challenge})"
    return "ACCEPTED 200"


def main():
    # Failures are logged with a fixed reason code only: the access token
    # and the proof never appear in logs or error responses.
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(message)s")

    # The client generates its proof key. The authorization server would
    # have stored the public key thumbprint (cnf.jkt) on the token.
    client_key = ECKey.generate_key("P-256", private=True)
    attacker_key = ECKey.generate_key("P-256", private=True)
    jkt = client_key.thumbprint()

    tokens = {
        ACCESS_TOKEN: Token(ACCESS_TOKEN, jkt=jkt),
        # A legacy token without key binding keeps working over Bearer.
        "legacy-access-token": Token("legacy-access-token", jkt=None),
    }
    replay_store = DatabaseReplayStore()
    protector = build_protector(tokens, replay_store)

    now = int(time.time())
    valid_proof = sign_dpop_proof(
        client_key, ACCESS_TOKEN, "GET", RESOURCE_URL, "proof-1", now
    )

    print("1. legitimate DPoP request:")
    print("  ", call_resource(protector, valid_proof, ACCESS_TOKEN))

    print("2. the same proof replayed:")
    print("  ", call_resource(protector, valid_proof, ACCESS_TOKEN))

    print("3. a proof signed with another key (stolen token, wrong key):")
    foreign_proof = sign_dpop_proof(
        attacker_key, ACCESS_TOKEN, "GET", RESOURCE_URL, "proof-2", now
    )
    print("  ", call_resource(protector, foreign_proof, ACCESS_TOKEN))

    print("4. a proof bound to another HTTP method:")
    wrong_method_proof = sign_dpop_proof(
        client_key, ACCESS_TOKEN, "POST", RESOURCE_URL, "proof-3", now
    )
    print("  ", call_resource(protector, wrong_method_proof, ACCESS_TOKEN))

    print("5. the bound token presented as plain Bearer:")
    bearer_request = OAuth2Request(
        "GET", RESOURCE_URL, headers={"Authorization": f"Bearer {ACCESS_TOKEN}"}
    )
    try:
        protector.validate_request(None, bearer_request)
    except InvalidDPoPProofError:
        print("   REJECTED: the DPoP-bound token cannot bypass the proof check")

    print("6. an unbound legacy token still works over plain Bearer:")
    legacy_request = OAuth2Request(
        "GET",
        RESOURCE_URL,
        headers={"Authorization": "Bearer legacy-access-token"},
    )
    protector.validate_request(None, legacy_request)
    print("   ACCEPTED: unbound legacy token")

    print("7. replay storage outage (no Bearer downgrade):")
    replay_store.simulated_outage = True
    outage_proof = sign_dpop_proof(
        client_key, ACCESS_TOKEN, "GET", RESOURCE_URL, "proof-4", now
    )
    print("  ", call_resource(protector, outage_proof, ACCESS_TOKEN))
    replay_store.simulated_outage = False

    print("8. a failed request did not consume its jti:")
    # proof-4 was rejected by the storage outage, so presenting it now works
    print("  ", call_resource(protector, outage_proof, ACCESS_TOKEN))


if __name__ == "__main__":
    main()
