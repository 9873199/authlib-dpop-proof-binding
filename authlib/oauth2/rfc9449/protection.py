"""authlib.oauth2.rfc9449.protection.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

ResourceProtector extension that enables DPoP on a resource server.
"""

from ..rfc6749.errors import MissingAuthorizationError
from ..rfc6749.resource_protector import ResourceProtector
from .validator import DPoPTokenValidator

__all__ = ["DPoPProtection"]


class DPoPProtection:
    """ResourceProtector extension for DPoP-bound access tokens.

    Register it together with a :class:`DPoPTokenValidator`::

        require_oauth = ResourceProtector()
        require_oauth.register_token_validator(MyDPoPTokenValidator())
        require_oauth.register_extension(DPoPProtection())

    Once enabled:

    - requests using the ``DPoP`` authorization scheme are validated with
      the proof carried in the ``DPoP`` header;
    - a token bound to a ``cnf.jkt`` confirmation cannot be used through
      the plain ``Bearer`` scheme: presenting it without a proof is
      rejected instead of falling back to Bearer validation;
    - protectors without the extension keep their previous behavior, so
      existing deployments stay compatible.
    """

    def __call__(self, protector):
        protector.register_hook(
            self._validate_request,
            replace=ResourceProtector.validate_request,
        )

    def _validate_request(self, protector, original, scopes, request, **kwargs):
        # Use the (possibly extended) parser, so extensions such as
        # FormEncodedBodyToken keep working for the Bearer scheme.
        try:
            validator, token_string = protector.parse_request_authorization(request)
        except MissingAuthorizationError:
            # A DPoP-only protector must advertise the canonical DPoP
            # challenge rather than its lower-cased token type.
            if protector._default_auth_type == "dpop":
                raise MissingAuthorizationError(
                    "DPoP", protector._default_realm
                ) from None
            raise
        if isinstance(validator, DPoPTokenValidator):
            return validator.validate_dpop_request(
                token_string, request, scopes=scopes, **kwargs
            )

        validator.validate_request(request)
        token = validator.authenticate_token(token_string)
        validator.validate_token(token, scopes, request, **kwargs)

        # A DPoP-bound token must never pass through the plain Bearer
        # validator when DPoP protection is enabled on this protector.
        dpop_validator = protector._token_validators.get("dpop")
        if dpop_validator is not None:
            dpop_validator.validate_bearer_bypass(token)
        return token
