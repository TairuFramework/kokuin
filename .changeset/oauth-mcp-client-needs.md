---
"@kokuin/oauth": patch
---

`exchangeCode` and `refreshToken` accept `extraParams` (for example `resource` per RFC 8707, or `scope`), which never override the grant's own fields. `fetchOAuthJSON` accepts `method: 'GET'` for metadata reads with no body. The loopback rule now also accepts `http` on `*.localhost` hosts.
