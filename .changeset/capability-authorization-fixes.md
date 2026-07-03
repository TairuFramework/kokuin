---
"@kokuin/capability": minor
"@kokuin/token": minor
---

Harden the capability/token authorization model:

- Reject permission prefix escalation in `hasPartsMatch` — a grant more specific than the request no longer authorizes the broader request, and there is no implicit descent (use a trailing `*`).
- Enforce the `authentication` relationship when an explicit `kid` is present, so a key listed only under `assertionMethod` cannot sign tokens.
- Add an `audience` option to `verifyToken` that validates the invocation token's `aud` (and rejects unsigned/`alg:none` tokens when set).
- Sign revocation records so only a token's own issuer can revoke it; the checker re-verifies the record signature on use.

BREAKING: `RevocationBackend.isRevoked(jti)` is replaced by `get(jti)`, and `RevocationRecord` is now a signed token (`SignedToken<RevocationClaims>`) rather than a plain object.
