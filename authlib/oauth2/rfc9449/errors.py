"""authlib.oauth2.rfc9449.errors.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Errors raised while validating DPoP proofs per :rfc:`9449`.

Error messages never contain the access token or the proof itself.
"""

from ..rfc6749.errors import OAuth2Error

__all__ = ["InvalidDPoPProofError"]


class InvalidDPoPProofError(OAuth2Error):
    """The DPoP proof is missing, malformed, or invalid.

    Per :rfc:`9449#section-7.3`, this is an ``invalid_dpop_proof`` error
    answered with HTTP 401 and a ``DPoP`` WWW-Authenticate challenge.
    """

    error = "invalid_dpop_proof"
    description = "The DPoP proof is invalid."
    status_code = 401

    def __init__(self, description=None):
        super().__init__(description=description)

    def get_headers(self):
        headers = super().get_headers()
        extras = [f'error="{self.error}"']
        error_description = self.get_error_description()
        extras.append(f'error_description="{error_description}"')
        headers.append(("WWW-Authenticate", "DPoP " + ", ".join(extras)))
        return headers
