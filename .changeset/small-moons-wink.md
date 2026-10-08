---
"@kokuin/capability": patch
---

Export TokenRevokedError, isTokenRevokedError and RevocationClaims. createRevocationChecker now treats a record whose payload is not an object, or whose iss is not a string, as no evidence rather than failing. A record now revokes only when its payload has rev: true and names the checked jti: a genuine revocation of another jti, or any other token its issuer signed, filed under this jti is no evidence, on the verified path and the denied-key path alike
