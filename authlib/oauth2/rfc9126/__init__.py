"""authlib.oauth2.rfc9126.
~~~~~~~~~~~~~~~~~~~~~~~~~

Implementation of OAuth 2.0 Pushed Authorization Requests (PAR),
:rfc:`9126`.

The package provides:

* :class:`PushedAuthorizationEndpoint`, the authenticated push endpoint.
* :class:`PushedAuthorizationRequests`, the server extension that resolves
  ``request_uri`` handles and enforces the frozen request.
* :class:`PushedAuthorizationGrantExtension`, the atomic consumption hook for
  authorization grants.
* :class:`MemoryPushedAuthorizationStorage`, a thread-safe in-memory reference
  implementation of :class:`PushedAuthorizationStorage`.
"""

from .endpoint import PushedAuthorizationEndpoint
from .errors import InvalidRequestUriError
from .errors import PushedAuthorizationServerError
from .extension import PushedAuthorizationGrantExtension
from .extension import PushedAuthorizationRequests
from .extension import arm_par_consumption
from .payload import FrozenAuthorizationPayload
from .storage import DECISION_APPROVED
from .storage import DECISION_DENIED
from .storage import REQUEST_URI_PREFIX
from .storage import STATUS_ACTIVE
from .storage import STATUS_CONSUMED
from .storage import STATUS_FAILED
from .storage import MemoryPushedAuthorizationStorage
from .storage import PushedAuthorizationClientMismatch
from .storage import PushedAuthorizationConflict
from .storage import PushedAuthorizationExpired
from .storage import PushedAuthorizationNotFound
from .storage import PushedAuthorizationRecord
from .storage import PushedAuthorizationStorage
from .storage import build_request_uri
from .storage import digest_handle
from .storage import handle_from_request_uri
from .storage import is_pushed_authorization_request_uri

#: Alternate name for the server extension, matching earlier PAR work.
PushedAuthorizationRequest = PushedAuthorizationRequests

__all__ = [
    "DECISION_APPROVED",
    "DECISION_DENIED",
    "REQUEST_URI_PREFIX",
    "STATUS_ACTIVE",
    "STATUS_CONSUMED",
    "STATUS_FAILED",
    "FrozenAuthorizationPayload",
    "InvalidRequestUriError",
    "MemoryPushedAuthorizationStorage",
    "PushedAuthorizationClientMismatch",
    "PushedAuthorizationConflict",
    "PushedAuthorizationEndpoint",
    "PushedAuthorizationExpired",
    "PushedAuthorizationGrantExtension",
    "PushedAuthorizationNotFound",
    "PushedAuthorizationRecord",
    "PushedAuthorizationRequest",
    "PushedAuthorizationRequests",
    "PushedAuthorizationServerError",
    "PushedAuthorizationStorage",
    "arm_par_consumption",
    "build_request_uri",
    "digest_handle",
    "handle_from_request_uri",
    "is_pushed_authorization_request_uri",
]
