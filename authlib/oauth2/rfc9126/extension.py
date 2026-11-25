"""Server and grant extensions that connect a PAR handle to the authorization
endpoint and to the authorization code grant.
"""

import hmac
import logging

from ..rfc6749 import AuthorizationServer
from ..rfc6749 import InvalidRequestError
from ..rfc6749 import OAuth2Error
from ..rfc6749.grants.base import AuthorizationEndpointMixin
from .errors import InvalidRequestUriError
from .errors import PushedAuthorizationServerError
from .payload import FrozenAuthorizationPayload
from .storage import DECISION_APPROVED
from .storage import DECISION_DENIED
from .storage import STATUS_ACTIVE
from .storage import PushedAuthorizationClientMismatch
from .storage import PushedAuthorizationConflict
from .storage import PushedAuthorizationExpired
from .storage import PushedAuthorizationNotFound
from .storage import digest_handle
from .storage import handle_from_request_uri
from .storage import is_pushed_authorization_request_uri

log = logging.getLogger(__name__)

__all__ = [
    "PushedAuthorizationGrantExtension",
    "PushedAuthorizationRequests",
    "arm_par_consumption",
]


def _snapshot_datalist(datalist):
    return {name: list(values) for name, values in datalist.items()}


def _map_store_error(error):
    if isinstance(
        error,
        (
            PushedAuthorizationNotFound,
            PushedAuthorizationExpired,
            PushedAuthorizationClientMismatch,
            PushedAuthorizationConflict,
        ),
    ):
        return InvalidRequestUriError()
    return PushedAuthorizationServerError()


class PushedAuthorizationGrantExtension:
    """Grant extension that atomically consumes the PAR handle at the final
    allow/deny submission.

    Register it like :class:`~authlib.oauth2.rfc7636.CodeChallenge`::

        server.register_grant(
            AuthorizationCodeGrant,
            [par.grant_extension, CodeChallenge(required=True)],
        )

    Page renders, logins and refreshes only call ``get_consent_grant`` and
    therefore only *read* the handle. The compare-and-set consumption runs in
    a ``replace`` hook around ``create_authorization_response``, so two
    concurrent confirmations cannot both issue a code.
    """

    def __init__(self, storage):
        self.storage = storage

    def __call__(self, grant):
        if getattr(grant, "_par_consumption_armed", False):
            return
        grant._par_consumption_armed = True
        grant.register_hook(
            self._around_create_authorization_response,
            replace=AuthorizationEndpointMixin.create_authorization_response,
        )

    def _around_create_authorization_response(
        self, grant, original, redirect_uri, grant_user
    ):
        request = grant.request
        record = getattr(request, "par_record", None)
        if record is None:
            # Not a PAR request: leave the ordinary grant flow untouched.
            return original(redirect_uri, grant_user)

        decision = DECISION_APPROVED if grant_user else DECISION_DENIED
        try:
            consumed = self.storage.consume(
                record.handle,
                client_id=record.client_id,
                version=record.version,
                decision=decision,
            )
        except Exception as error:
            log.warning(
                "PAR consume rejected handle=%s reason=%s",
                digest_handle(record.handle),
                type(error).__name__,
            )
            raise _map_store_error(error) from error

        if not grant_user:
            # The original method raises AccessDeniedError. The handle is
            # already atomically recorded as a terminal denial.
            log.debug(
                "PAR consumed denial handle=%s",
                digest_handle(consumed.handle),
            )
            return original(redirect_uri, grant_user)

        try:
            response = original(redirect_uri, grant_user)
        except Exception as error:
            # The claim is committed: never release it back to "active". Mark
            # the record as terminally failed so a retry is deterministically
            # rejected and a fresh PAR is required.
            reason = type(error).__name__
            try:
                self.storage.mark_failed(
                    consumed.handle,
                    version=consumed.version,
                    reason=reason,
                )
            except Exception as mark_error:  # best effort
                log.error(
                    "PAR mark_failed errored handle=%s reason=%s",
                    digest_handle(consumed.handle),
                    type(mark_error).__name__,
                )
            log.error(
                "PAR issuance failed after consume handle=%s reason=%s",
                digest_handle(consumed.handle),
                reason,
            )
            if isinstance(error, OAuth2Error):
                raise
            raise PushedAuthorizationServerError() from error

        log.debug(
            "PAR consumed approval handle=%s",
            digest_handle(consumed.handle),
        )
        return response


def arm_par_consumption(grant, storage):
    """Idempotently attach the atomic consumption hook to a grant."""
    if not isinstance(grant, AuthorizationEndpointMixin):
        return None
    PushedAuthorizationGrantExtension(storage)(grant)


class PushedAuthorizationRequests:
    """Server extension implementing :rfc:`9126`.

    It registers the ``request_uri`` parameter, resolves a PAR handle before
    grant selection, enforces the strict front-channel parameter rule, arms the
    atomic consumption hook and registers
    :class:`~authlib.oauth2.rfc9126.PushedAuthorizationEndpoint`.

    Usage::

        storage = MemoryPushedAuthorizationStorage()
        par = PushedAuthorizationRequests(storage, expires_in=60)
        server.register_extension(par)
        server.register_grant(MyAuthorizationCodeGrant, [par.grant_extension])
    """

    #: Parameters allowed on the browser authorization request next to
    #: ``request_uri``. Every other known authorization parameter is rejected:
    #: the frozen pushed values must be the only source of truth.
    ALLOWED_FRONTCHANNEL_PARAMETERS = frozenset({"client_id", "request_uri"})

    def __init__(
        self,
        storage=None,
        *,
        expires_in=60,
        auto_arm_consumption=True,
        register_endpoint=True,
    ):
        if storage is None:
            from .storage import MemoryPushedAuthorizationStorage

            storage = MemoryPushedAuthorizationStorage()
        self.storage = storage
        self.expires_in = expires_in
        self.auto_arm_consumption = auto_arm_consumption
        self.register_endpoint = register_endpoint

    def __call__(self, server: AuthorizationServer):
        server.par_storage = self.storage
        server.register_authorization_parameters({"request_uri": str})
        server.register_hook(
            self._before_get_authorization_grant,
            before=AuthorizationServer.get_authorization_grant,
        )
        server.register_hook(
            self._after_get_authorization_grant,
            after=AuthorizationServer.get_authorization_grant,
        )
        if self.register_endpoint:
            from .endpoint import PushedAuthorizationEndpoint

            server.register_endpoint(
                PushedAuthorizationEndpoint(
                    server=server,
                    storage=self.storage,
                    expires_in=self.expires_in,
                )
            )

    @property
    def grant_extension(self):
        """The grant extension to pass to ``server.register_grant``."""
        return PushedAuthorizationGrantExtension(self.storage)

    def _before_get_authorization_grant(self, server: AuthorizationServer, request):
        request_uri = request.payload.data.get("request_uri")
        if not is_pushed_authorization_request_uri(request_uri):
            # Another kind of request_uri (e.g. JAR) or a plain request: let
            # another extension/the normal flow handle it.
            return

        handle = handle_from_request_uri(request_uri)
        frontchannel = _snapshot_datalist(request.payload.datalist)

        try:
            record = self.storage.get(handle)
        except Exception as error:
            log.error(
                "PAR storage get failed handle=%s reason=%s",
                digest_handle(handle),
                type(error).__name__,
            )
            raise PushedAuthorizationServerError() from error

        if record is None:
            log.info("PAR unknown handle=%s", digest_handle(handle))
            raise InvalidRequestUriError()

        if record.status != STATUS_ACTIVE:
            log.info(
                "PAR terminal handle=%s status=%s",
                digest_handle(handle),
                record.status,
            )
            raise InvalidRequestUriError()

        try:
            now = self.storage.now()
        except Exception as error:
            raise PushedAuthorizationServerError() from error

        if record.expires_at <= now:
            log.info("PAR expired handle=%s", digest_handle(handle))
            raise InvalidRequestUriError()

        presented_client_id = request.payload.client_id
        if not presented_client_id:
            raise InvalidRequestError(
                "The 'client_id' parameter is required with 'request_uri'."
            )
        if not hmac.compare_digest(str(presented_client_id), str(record.client_id)):
            log.warning("PAR client mismatch handle=%s", digest_handle(handle))
            raise InvalidRequestUriError()

        # Freeze: replace, never merge. The raw front-channel values are kept
        # only for the explicit override check.
        request._par_frontchannel = frontchannel
        request.par_record = record
        request.payload = FrozenAuthorizationPayload(record.params)

    def _after_get_authorization_grant(self, server: AuthorizationServer, grant):
        request = grant.request
        frontchannel = getattr(request, "_par_frontchannel", None)
        if frontchannel is None:
            return

        known_parameters = set(grant.authorization_parameters)
        known_parameters.update(server.authorization_parameters)
        for name in frontchannel:
            if (
                name in known_parameters
                and name not in self.ALLOWED_FRONTCHANNEL_PARAMETERS
            ):
                raise InvalidRequestError(
                    f"The '{name}' parameter cannot be supplied at the "
                    "authorization endpoint together with 'request_uri'; "
                    "it is fixed by the pushed authorization request."
                )

        if self.auto_arm_consumption:
            arm_par_consumption(grant, self.storage)
