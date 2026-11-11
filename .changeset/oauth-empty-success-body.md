---
"@kokuin/oauth": patch
---

`fetchOAuthJSON` resolves `undefined` for an empty (or whitespace-only) success body by default, as RFC 7009 token revocation answers `200` with no content. Pass `allowEmpty: false` to reject it as invalid JSON. Token endpoints that answer empty now fail with `OAuth token response was not an object`.
