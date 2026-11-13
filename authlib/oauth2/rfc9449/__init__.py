"""authlib.oauth2.rfc9449.
~~~~~~~~~~~~~~~~~~~~~~~~

OAuth 2.0 Demonstrating Proof of Possession (DPoP).

This module implements the resource server side of :rfc:`9449`: it
validates DPoP proofs presented with already issued access tokens. The
authorization endpoint of DPoP is not implemented.

https://www.rfc-editor.org/rfc/rfc9449
"""

from .protection import DPoPProtection
from .validator import DPoPProof
from .validator import DPoPReplayStore
from .validator import DPoPTokenValidator
from .validator import InvalidDPoPProofError
from .validator import canonical_request_url
from .validator import compute_ath

__all__ = [
    "DPoPProtection",
    "DPoPProof",
    "DPoPReplayStore",
    "DPoPTokenValidator",
    "InvalidDPoPProofError",
    "canonical_request_url",
    "compute_ath",
]
