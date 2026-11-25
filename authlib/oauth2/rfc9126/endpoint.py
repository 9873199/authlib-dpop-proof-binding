import hmac
import logging

from ..rfc6749 import InvalidRequestError
from ..rfc6749 import JsonResponse
from ..rfc6749 import OAuth2Error
from ..rfc6749.grants.base import validate_no_repeated_parameter
from ..rfc6749.token_endpoint import TokenEndpoint
from .errors import PushedAuthorizationServerError
from .storage import build_request_uri
from .storage import digest_handle

log = logging.getLogger(__name__)


class PushedAuthorizationEndpoint(TokenEndpoint):
    """The :rfc:`9126` pushed authorization request endpoint.

    Register it like any other endpoint and wire an HTTP route to it::

        server.register_endpoint(PushedAuthorizationEndpoint(storage=par_storage))


        @app.route("/oauth/par", methods=["POST"])
        def pushed_authorization_request():
            return server.create_endpoint_response("pushed_authorization")

    The endpoint authenticates the client with the token endpoint rules,
    validates the authorization parameters with the registered grants and
    extensions, then asks the injected storage to persist the frozen request.
    """

    ENDPOINT_NAME = "pushed_authorization"

    #: PAR uses the same client authentication methods as the token endpoint.
    CLIENT_AUTH_METHODS = ["client_secret_basic", "client_secret_post", "none"]

    #: Default lifetime of the handle, in seconds. RFC 9126 suggests 5..600.
    DEFAULT_EXPIRES_IN = 60

    def __init__(self, server=None, storage=None, expires_in=None):
        super().__init__(server)
        self.storage = storage
        self.expires_in = (
            expires_in if expires_in is not None else self.DEFAULT_EXPIRES_IN
        )

    def create_endpoint_response(self, request):
        if request.method != "POST":
            raise InvalidRequestError(
                "The pushed authorization request endpoint only accepts POST.",
                status_code=405,
            )

        if "request_uri" in request.payload.data:
            raise InvalidRequestError(
                "The 'request_uri' parameter MUST NOT be sent to the PAR endpoint."
            )

        storage = self.storage or getattr(self.server, "par_storage", None)
        if storage is None:
            raise RuntimeError(
                "PushedAuthorizationEndpoint requires a 'storage' implementation."
            )

        # RFC 9126 §2.1 step 1: authenticate the client like the token endpoint.
        client = self.authenticate_endpoint_client(request)

        presented_client_id = request.payload.client_id
        if not presented_client_id:
            raise InvalidRequestError("Missing 'client_id' in pushed request.")
        if not hmac.compare_digest(str(client.client_id), str(presented_client_id)):
            raise InvalidRequestError(
                "The 'client_id' does not match the authenticated client."
            )

        # Reuse the exact authorization endpoint validation, including grant
        # extensions such as PKCE. There is no resource owner yet.
        validate_no_repeated_parameter(request, self.server.authorization_parameters)
        grant = self.server.get_authorization_grant(request)
        grant.validate_no_multiple_request_parameter(request)
        try:
            grant.validate_authorization_request()
        except OAuth2Error as error:
            # PAR errors are token-endpoint style JSON, never redirects.
            error.redirect_uri = None
            error.redirect_fragment = False
            error.response_mode = None
            raise

        params = self._collect_parameters(grant, request)

        try:
            record = storage.create(
                client_id=client.client_id,
                params=params,
                expires_in=self.expires_in,
            )
        except Exception as error:  # storage backend failure
            log.error("PAR storage create failed: %s", type(error).__name__)
            raise PushedAuthorizationServerError() from error

        request_uri = build_request_uri(record.handle)
        log.debug(
            "Pushed authorization stored handle=%s",
            digest_handle(record.handle),
        )
        return JsonResponse(
            {"request_uri": request_uri, "expires_in": self.expires_in},
            status_code=201,
        )

    @staticmethod
    def _collect_parameters(grant, request):
        """Copy only declared authorization parameters into frozen storage.

        Client authentication fields (``client_secret``, assertions, ...) and
        consent-form fields are not part of the authorization request.
        """
        datalist = request.payload.datalist
        params = {}
        for name in grant.authorization_parameters:
            values = datalist.get(name)
            if values:
                params[name] = list(values)

        # Persist the resolved scope (including a client default) rather than
        # recomputing a potentially different one on the browser leg.
        if request.scope is not None:
            params["scope"] = [request.scope]
        return params
