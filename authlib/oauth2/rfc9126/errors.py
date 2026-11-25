from ..base import OAuth2Error

__all__ = [
    "InvalidRequestUriError",
    "PushedAuthorizationServerError",
]


class InvalidRequestUriError(OAuth2Error):
    """The ``request_uri`` is unknown, expired, already consumed, failed, or
    not bound to the presented ``client_id``.

    All these cases use the same error code on purpose: an attacker must not
    be able to distinguish a valid handle from an invalid one.
    """

    error = "invalid_request_uri"
    description = (
        "The 'request_uri' is invalid, expired, already used, or does not "
        "match the 'client_id'."
    )
    status_code = 400


class PushedAuthorizationServerError(OAuth2Error):
    """The pushed authorization request storage failed."""

    error = "server_error"
    description = "The authorization server could not process the request."
    status_code = 500
