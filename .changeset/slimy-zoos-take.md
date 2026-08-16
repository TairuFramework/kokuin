---
"@kokuin/token": minor
---

Split the JWE implementation into the new @kokuin/jwe package. Add the DIDMethodResolver interface and method registry so tokens can be issued and verified for resolver-backed methods such as did:kokuin:, and resolve did:peer:4 issuers from a cache or resolver. resolveIssuer and resolveIssuerWithDoc now take a single params object.
