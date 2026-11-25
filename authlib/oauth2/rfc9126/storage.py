"""Storage contract for :rfc:`9126` pushed authorization requests.

The storage keeps the *frozen*, validated authorization request behind an
opaque handle. It is the single source of truth for the consumption state,
which is why the final user decision is committed through the atomic
:meth:`PushedAuthorizationStorage.consume` compare-and-set operation.

A minimal backend implements four methods:

* :meth:`PushedAuthorizationStorage.create` stores a new request and generates
  the opaque handle and its unique version.
* :meth:`PushedAuthorizationStorage.get` is a non-consuming read used to render
  the authorization page, so page loads and refreshes do not consume the
  handle.
* :meth:`PushedAuthorizationStorage.consume` atomically transitions an active
  record to a terminal state, guarded by its version and client identity.
* :meth:`PushedAuthorizationStorage.mark_failed` marks a claimed record as
  terminally failed when code issuance or a callback fails after the claim.
"""

from __future__ import annotations

import hashlib
import hmac
import threading
import time
from dataclasses import dataclass
from dataclasses import replace
from typing import Protocol

from authlib.common.security import generate_token

__all__ = [
    "DECISION_APPROVED",
    "DECISION_DENIED",
    "REQUEST_URI_PREFIX",
    "STATUS_ACTIVE",
    "STATUS_CONSUMED",
    "STATUS_FAILED",
    "MemoryPushedAuthorizationStorage",
    "PushedAuthorizationClientMismatch",
    "PushedAuthorizationConflict",
    "PushedAuthorizationExpired",
    "PushedAuthorizationNotFound",
    "PushedAuthorizationRecord",
    "PushedAuthorizationStorage",
    "build_request_uri",
    "digest_handle",
    "handle_from_request_uri",
    "is_pushed_authorization_request_uri",
]

#: RFC 9126 §2.2 recommended URN namespace for the handle.
REQUEST_URI_PREFIX = "urn:ietf:params:oauth:request_uri:"

#: The request is stored and can be read until a decision is committed.
STATUS_ACTIVE = "active"

#: A decision was atomically committed. This is terminal.
STATUS_CONSUMED = "consumed"

#: The record was claimed but code issuance or a callback failed afterwards.
#: This is terminal too: the handle can never become active again.
STATUS_FAILED = "failed"

DECISION_APPROVED = "approved"
DECISION_DENIED = "denied"


class PushedAuthorizationStoreError(Exception):
    """Base class for storage contract errors."""


class PushedAuthorizationNotFound(PushedAuthorizationStoreError):
    """The handle does not reference any stored request."""


class PushedAuthorizationExpired(PushedAuthorizationStoreError):
    """The handle is past its expiration time."""


class PushedAuthorizationClientMismatch(PushedAuthorizationStoreError):
    """The handle was pushed by another client."""


class PushedAuthorizationConflict(PushedAuthorizationStoreError):
    """The record is not active anymore or the version does not match.

    Two concurrent decisions race on the same version: only one compare-and-set
    can succeed, the other gets this error.
    """


@dataclass
class PushedAuthorizationRecord:
    """A frozen pushed authorization request.

    :param handle: the opaque, unguessable reference (without the URN prefix).
    :param client_id: the authenticated client that pushed the request.
    :param params: the frozen authorization parameters, as a multi-value mapping.
    :param expires_at: absolute expiration timestamp, using the storage clock.
    :param version: unique compare-and-set token, rotated on every transition.
    :param status: one of :data:`STATUS_ACTIVE`, :data:`STATUS_CONSUMED`,
        :data:`STATUS_FAILED`.
    :param decision: :data:`DECISION_APPROVED` or :data:`DECISION_DENIED` once
        consumed.
    """

    handle: str
    client_id: str
    params: dict[str, list[str]]
    expires_at: float
    version: str
    status: str = STATUS_ACTIVE
    decision: str | None = None
    consumed_at: float | None = None
    failure_reason: str | None = None

    def is_expired(self, now: float | None = None) -> bool:
        if now is None:
            now = time.time()
        return self.expires_at <= now


class PushedAuthorizationStorage(Protocol):
    """Minimal storage protocol for pushed authorization requests.

    Implementations MUST make :meth:`consume` atomic: the check of the current
    status, client and version together with the transition to the terminal
    state has to be a single compare-and-set operation (a conditional ``UPDATE``
    or an equivalent row lock). This is what prevents two concurrent
    confirmations from issuing two authorization codes.
    """

    def now(self) -> float:
        """Return the current time, in the same unit as :meth:`create` uses."""

    def create(
        self,
        *,
        client_id: str,
        params: dict[str, list[str]],
        expires_in: int,
    ) -> PushedAuthorizationRecord:
        """Store a validated request and generate its opaque handle/version."""

    def get(self, handle: str) -> PushedAuthorizationRecord | None:
        """Return the record without consuming it, or ``None``."""

    def consume(
        self,
        handle: str,
        *,
        client_id: str,
        version: str,
        decision: str,
    ) -> PushedAuthorizationRecord:
        """Atomically claim an active record with a matching client/version.

        :raises PushedAuthorizationNotFound: unknown handle.
        :raises PushedAuthorizationClientMismatch: bound to another client.
        :raises PushedAuthorizationExpired: past ``expires_at``.
        :raises PushedAuthorizationConflict: not active or stale version.
        """

    def mark_failed(
        self,
        handle: str,
        *,
        version: str,
        reason: str,
    ) -> PushedAuthorizationRecord:
        """Mark a claimed record as terminally failed after an issuance error."""


class MemoryPushedAuthorizationStorage:
    """Thread-safe in-memory reference implementation.

    It is suitable for tests and single-process deployments. The lock makes the
    compare-and-set in :meth:`consume` atomic across threads. Pass a controlled
    ``time_func`` to test expiration boundaries without sleeping.
    """

    def __init__(self, *, time_func=time.time, handle_length: int = 48):
        self.time_func = time_func
        self.handle_length = handle_length
        self._records: dict[str, PushedAuthorizationRecord] = {}
        self._lock = threading.RLock()

    def now(self) -> float:
        return self.time_func()

    @staticmethod
    def _snapshot(record: PushedAuthorizationRecord):
        """Return a defensive copy so callers cannot mutate stored state."""
        return replace(
            record,
            params={name: list(values) for name, values in record.params.items()},
        )

    def _generate_handle(self) -> str:
        return generate_token(self.handle_length)

    def _generate_version(self) -> str:
        return generate_token(32)

    def create(
        self,
        *,
        client_id: str,
        params: dict[str, list[str]],
        expires_in: int,
    ) -> PushedAuthorizationRecord:
        with self._lock:
            handle = self._generate_handle()
            while handle in self._records:
                handle = self._generate_handle()

            record = PushedAuthorizationRecord(
                handle=handle,
                client_id=client_id,
                params={name: list(values) for name, values in params.items()},
                expires_at=self.now() + float(expires_in),
                version=self._generate_version(),
            )
            self._records[handle] = record
            return self._snapshot(record)

    def get(self, handle: str) -> PushedAuthorizationRecord | None:
        with self._lock:
            record = self._records.get(handle)
            return self._snapshot(record) if record is not None else None

    def consume(
        self,
        handle: str,
        *,
        client_id: str,
        version: str,
        decision: str,
    ) -> PushedAuthorizationRecord:
        with self._lock:
            record = self._records.get(handle)
            if record is None:
                raise PushedAuthorizationNotFound()

            if not hmac.compare_digest(str(record.client_id), str(client_id)):
                raise PushedAuthorizationClientMismatch()

            if record.expires_at <= self.now():
                raise PushedAuthorizationExpired()

            if record.status != STATUS_ACTIVE or not hmac.compare_digest(
                record.version, str(version)
            ):
                raise PushedAuthorizationConflict(record.status)

            record.status = STATUS_CONSUMED
            record.decision = decision
            record.consumed_at = self.now()
            record.version = self._generate_version()
            return self._snapshot(record)

    def mark_failed(
        self,
        handle: str,
        *,
        version: str,
        reason: str,
    ) -> PushedAuthorizationRecord:
        with self._lock:
            record = self._records.get(handle)
            if record is None:
                raise PushedAuthorizationNotFound()
            if not hmac.compare_digest(record.version, str(version)):
                raise PushedAuthorizationConflict(record.status)

            record.status = STATUS_FAILED
            record.failure_reason = reason
            record.version = self._generate_version()
            return self._snapshot(record)


def build_request_uri(handle: str) -> str:
    """Build the ``request_uri`` URN for an opaque handle."""
    return REQUEST_URI_PREFIX + handle


def is_pushed_authorization_request_uri(value) -> bool:
    """Tell whether ``value`` is a PAR handle URN managed by this module."""
    return (
        isinstance(value, str)
        and value.startswith(REQUEST_URI_PREFIX)
        and len(value) > len(REQUEST_URI_PREFIX)
    )


def handle_from_request_uri(request_uri: str) -> str:
    """Extract the opaque handle from a PAR ``request_uri`` URN."""
    return request_uri[len(REQUEST_URI_PREFIX) :]


def digest_handle(handle: str) -> str:
    """Return a short, non-reversible digest of a handle for safe logging.

    Logs MUST use this instead of the raw ``request_uri``/handle.
    """
    return hashlib.sha256(str(handle).encode("utf-8")).hexdigest()[:12]
