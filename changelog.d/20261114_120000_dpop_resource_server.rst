Added
~~~~~

- Resource servers can validate DPoP-bound access tokens per :rfc:`9449`
  with the new :class:`~authlib.oauth2.rfc9449.DPoPTokenValidator` and
  :class:`~authlib.oauth2.rfc9449.DPoPProtection` extension. ES256 proofs
  are checked against the token ``cnf.jkt`` confirmation, the request
  (``htm``/``htu``) and the access token hash (``ath``), with atomic
  replay protection. Tokens carrying a confirmation can no longer bypass
  the check through the plain Bearer scheme.
