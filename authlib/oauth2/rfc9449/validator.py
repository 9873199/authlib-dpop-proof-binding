"""authlib.oauth2.rfc9449.validator.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Resource server validation of DPoP proofs bound to access tokens, per
:rfc:`9449`. Only the validation of already issued tokens is implemented;
the authorization endpoint parts of DPoP are out of scope.
"""

import hashlib
import hmac
import json
import logging
import time
from dataclasses import dataclass
from urllib.parse import urlsplit

from joserfc.errors import JoseError
from joserfc.jwk import ECKey
from joserfc.jws import JWSRegistry
from joserfc.jws import extract_compact
from joserfc.jws import verify_compact

from authlib.common.encoding import to_bytes
from authlib.common.encoding import to_unicode
from authlib.common.encoding import urlsafe_b64encode
from authlib.oauth2.rfc6750.validator import BearerTokenValidator

from .errors import InvalidDPoPProofError

__all__ = [
    "DPoPProof",
    "DPoPReplayStore",
    "DPoPTokenValidator",
    "canonical_request_url",
    "compute_ath",
]

logger = logging.getLogger(__name__)

#: Only ES256 (EC P-256) is supported. Restricting the JWS registry to this
#: single algorithm also rejects "none", symmetric algorithms and every other
#: signing algorithm before the signature is checked.
SUPPORTED_ALGORITHM = "ES256"
SUPPORTED_CURVE = "P-256"
DPOP_PROOF_TYPE = "dpop+jwt"

#: Header parameters that would make the resource server fetch a key, which
#: DPoP forbids: the key is always carried inline in the "jwk" parameter.
FORBIDDEN_HEADER_PARAMETERS = ("jku", "x5u", "x5c", "x5t", "x5t#S256")


@dataclass(frozen=True)
class DPoPProof:
    """A parsed and signature-verified DPoP proof."""

    jti: str
    iat: int
    jkt: str
    htm: str
    htu: str
    ath: str
    header: dict
    claims: dict


class DPoPReplayStore:
    """Interface of the storage that records used DPoP proofs.

    Implementations MUST make :meth:`register_proof_confirmation` atomic:
    the check-and-insert of ``(jkt, jti)`` has to run in one database
    operation (for instance an ``INSERT`` on a unique constraint, or
    ``SET NX`` in Redis). Two concurrent calls with the same key
    fingerprint and proof identifier MUST result in exactly one
    ``True`` return value.
    """

    def register_proof_confirmation(self, jkt, jti, expires_at):
        """Atomically record a used proof.

        :param jkt: RFC 7638 thumbprint of the public JWK that signed the
            proof.
        :param jti: unique identifier of the proof, taken from its ``jti``
            claim.
        :param expires_at: epoch timestamp at which the record may be
            deleted. It covers the whole interval during which the proof
            could still be accepted.
        :return: ``True`` if this is the first registration of the pair,
            ``False`` if the proof was already recorded (a replay).
        :raises Exception: any storage failure. The resource server treats
            it as a rejection and never falls back to plain Bearer
            validation.
        """
        raise NotImplementedError()


def compute_ath(token_string):
    """Compute the ``ath`` claim value of an access token.

    It is the base64url encoding without padding of the SHA-256 hash of
    the token string, per :rfc:`9449#section-4.2`.
    """
    digest = hashlib.sha256(to_bytes(token_string)).digest()
    return to_unicode(urlsafe_b64encode(digest))


def canonical_request_url(uri):
    """Canonicalize an HTTP URL for the ``htu`` comparison.

    The query and the fragment are removed. The scheme and the host are
    compared case-insensitively, the default ports (443 for HTTPS, 80 for
    HTTP) are folded, and the path is kept byte for byte: percent-encoded
    bytes are not decoded and the path case is not folded.

    :return: a ``(scheme, host, port, path)`` tuple, or ``None`` if the URL
        cannot be parsed.
    """
    try:
        parts = urlsplit(uri)
    except ValueError:
        return None

    if not parts.scheme or not parts.hostname:
        return None

    scheme = parts.scheme.lower()
    host = parts.hostname.lower()
    try:
        port = parts.port
    except ValueError:
        return None

    if port is None:
        port = 443 if scheme == "https" else 80 if scheme == "http" else None

    if port is None:
        return None

    return scheme, host, port, parts.path


class DPoPTokenValidator(BearerTokenValidator):
    """Validate access tokens presented with the ``DPoP`` scheme.

    Subclass it and implement the two storage-facing methods::

        class MyDPoPTokenValidator(DPoPTokenValidator):
            def authenticate_token(self, token_string):
                return Token.query.filter_by(access_token=token_string).first()

            def get_token_confirmation(self, token):
                # read cnf.jkt from the token model
                return token.get_dpop_jkt()

            def register_proof_confirmation(self, jkt, jti, expires_at):
                # atomic check-and-insert, delegating to DPoPReplayStore
                return replay_store.register_proof_confirmation(jkt, jti, expires_at)

    Register it on a :class:`~authlib.oauth2.rfc6749.ResourceProtector`
    together with :class:`~authlib.oauth2.rfc9449.DPoPProtection`::

        require_oauth = ResourceProtector()
        require_oauth.register_token_validator(MyDPoPTokenValidator())
        require_oauth.register_extension(DPoPProtection())

    :param replay_store: optional :class:`DPoPReplayStore`. When given,
        :meth:`register_proof_confirmation` delegates to it.
    :param proof_max_age: maximum age in seconds of an accepted proof.
    :param clock_skew: tolerance in seconds when checking the proof ``iat``.
    :param clock: callable returning the current epoch time, injectable for
        tests. Defaults to :func:`time.time`.
    """

    TOKEN_TYPE = "dpop"

    def __init__(
        self,
        replay_store=None,
        proof_max_age=60,
        clock_skew=0,
        clock=time.time,
        **extra_attributes,
    ):
        super().__init__(**extra_attributes)
        self.replay_store = replay_store
        self.proof_max_age = proof_max_age
        self.clock_skew = clock_skew
        self.clock = clock
        self._registry = JWSRegistry(algorithms=[SUPPORTED_ALGORITHM])

    def get_token_confirmation(self, token):
        """Return the ``cnf.jkt`` value bound to the token, or ``None``.

        Developers MUST re-implement this method to read the confirmation
        claim from their token model. A token that returns a non-empty
        value can only be used with a valid DPoP proof whose key
        thumbprint matches.
        """
        raise NotImplementedError()

    def register_proof_confirmation(self, jkt, jti, expires_at):
        """Record a used proof through the :class:`DPoPReplayStore`.

        Override this method instead of passing a store when the replay
        storage needs custom logic. The atomicity requirements of
        :meth:`DPoPReplayStore.register_proof_confirmation` apply.
        """
        if self.replay_store is None:
            raise NotImplementedError()
        return self.replay_store.register_proof_confirmation(jkt, jti, expires_at)

    def validate_dpop_request(self, token_string, request, scopes=None, **kwargs):
        """Run the full DPoP validation and return the authenticated token.

        The replay record is written only after the proof signature, the
        token state, its scopes, the key binding and the request binding
        have all been validated. A failed request never consumes a proof
        identifier.
        """
        proof = self._parse_proof(request)
        self._validate_timing(proof)

        # Token lookup, state and scope checks reuse the Bearer logic.
        # Their errors propagate unchanged and do not touch the replay
        # storage.
        self.validate_request(request)
        token = self.authenticate_token(token_string)
        self.validate_token(token, scopes, request, **kwargs)

        bound_jkt = self.get_token_confirmation(token)
        if not bound_jkt or bound_jkt != proof.jkt:
            self._reject("key_confirmation_mismatch")

        expected_ath = compute_ath(token_string)
        if not proof.ath or not _constant_time_equal(proof.ath, expected_ath):
            self._reject("ath_mismatch")

        if proof.htm != request.method:
            self._reject("htm_mismatch")

        if self._htu_mismatch(proof.htu, request.uri):
            self._reject("htu_mismatch")

        # The record must live until the proof leaves the acceptable window:
        # iat plus its maximum age, widened by the clock skew.
        expires_at = proof.iat + self.proof_max_age + self.clock_skew
        try:
            first_use = self.register_proof_confirmation(
                proof.jkt, proof.jti, expires_at
            )
        except Exception as exc:
            # A storage failure rejects the request; it never downgrades to
            # a plain Bearer acceptance.
            self._reject("replay_storage_error", exc)
        if not first_use:
            self._reject("replay_detected")
        return token

    def validate_bearer_bypass(self, token):
        """Reject a DPoP-bound token presented through the Bearer scheme.

        Called by :class:`DPoPProtection` when the request uses the
        ``Bearer`` authorization scheme while DPoP is enabled.
        """
        if self.get_token_confirmation(token):
            self._reject("bearer_bypass_forbidden")

    def _parse_proof(self, request):
        header_value = request.headers.get("DPoP")
        if not header_value:
            self._reject("missing_dpop_header")

        try:
            obj = extract_compact(to_bytes(header_value), registry=self._registry)
            header = dict(obj.protected)
            alg = self._registry.get_alg(header["alg"])
        except JoseError as exc:
            self._reject("malformed_proof", exc)
        except (KeyError, TypeError, ValueError) as exc:
            self._reject("malformed_proof", exc)

        self._validate_header(header)
        jwk = self._import_jwk(header.get("jwk"))

        try:
            if not verify_compact(obj, alg, jwk):
                self._reject("bad_signature")
        except (JoseError, ValueError, TypeError) as exc:
            self._reject("bad_signature", exc)

        try:
            claims = json.loads(obj.payload.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            self._reject("malformed_claims", exc)
        if not isinstance(claims, dict):
            self._reject("malformed_claims")

        jti = claims.get("jti")
        if not isinstance(jti, str) or not jti:
            self._reject("invalid_jti")
        # bool is a subclass of int: iat must be a genuine integer.
        iat = claims.get("iat")
        if not isinstance(iat, int) or isinstance(iat, bool):
            self._reject("invalid_iat")

        for name in ("htm", "htu", "ath"):
            if not isinstance(claims.get(name), str) or not claims.get(name):
                self._reject(f"invalid_{name}")

        return DPoPProof(
            jti=jti,
            iat=iat,
            jkt=jwk.thumbprint(),
            htm=claims["htm"],
            htu=claims["htu"],
            ath=claims["ath"],
            header=header,
            claims=claims,
        )

    def _validate_header(self, header):
        if header.get("typ") != DPOP_PROOF_TYPE:
            self._reject("invalid_typ")
        for name in FORBIDDEN_HEADER_PARAMETERS:
            if name in header:
                self._reject("forbidden_key_reference")
        if not isinstance(header.get("jwk"), dict):
            self._reject("missing_jwk")

    def _import_jwk(self, raw_jwk):
        if not isinstance(raw_jwk, dict):
            self._reject("missing_jwk")
        if raw_jwk.get("kty") != "EC":
            # "none" and symmetric algorithms are rejected upstream by the
            # restricted registry; an octet or RSA JWK can never verify an
            # ES256 proof anyway.
            self._reject("unsupported_key_type")
        if "d" in raw_jwk:
            # A private key must never be used to verify a proof: the
            # client only proves possession of the corresponding private
            # key.
            self._reject("private_or_symmetric_jwk")
        try:
            jwk = ECKey.import_key(raw_jwk)
        except (JoseError, ValueError, TypeError) as exc:
            self._reject("malformed_jwk", exc)
        if jwk.is_private:
            self._reject("private_or_symmetric_jwk")
        if jwk.curve_name != SUPPORTED_CURVE:
            self._reject("unsupported_curve")
        return jwk

    def _validate_timing(self, proof):
        now = self.clock()
        if proof.iat > now + self.clock_skew:
            self._reject("proof_in_the_future")
        if proof.iat < now - self.proof_max_age - self.clock_skew:
            self._reject("proof_too_old")

    def _htu_mismatch(self, claimed_htu, request_uri):
        claimed = canonical_request_url(claimed_htu)
        actual = canonical_request_url(request_uri)
        if claimed is None or actual is None:
            return True
        return claimed != actual

    def _reject(self, reason, exc=None):
        # Log only a fixed reason code: the token and the proof are never
        # written to the logs. Exception details stay at debug level.
        logger.warning("Rejected DPoP proof: %s", reason)
        if exc is not None:
            logger.debug("DPoP rejection detail for %s", reason, exc_info=exc)
        raise InvalidDPoPProofError() from exc


def _constant_time_equal(a, b):
    return hmac.compare_digest(a, b)
