---
"@kokuin/oauth": patch
---

`buildAuthorizationURL` omits the `scope` parameter when no scopes are requested, rather than sending an empty `scope=` that strict authorization servers reject (RFC 6749 makes `scope` optional).
