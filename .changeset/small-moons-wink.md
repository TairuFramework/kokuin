---
"@kokuin/capability": minor
---

Export TokenRevokedError, isTokenRevokedError and RevocationClaims. createRevocationChecker now treats a record whose payload is not an object, or whose iss is not a string, as no evidence rather than failing
