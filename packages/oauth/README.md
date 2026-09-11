# @kokuin/oauth

Generic OAuth 2.0 client primitives for kokuin: PKCE, hardened HTTP with
structured OAuth errors, the authorization-code and refresh-token exchanges, and
a pending-authorization orchestration + store port.

A true leaf package — depends only on `@sozai/runtime`, `@noble/hashes`, and
`@sozai/codec`. It owns no application-specific concern (no DID/credential
wrapping, no connector registry, no MCP resource discovery, no provider-specific
authorization policy).
