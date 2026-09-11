# `@kokuin/oauth` — generic OAuth 2.0 client primitives — completed

**Status:** complete
**Date:** 2026-09-11
**Branch:** `feat/oauth-package-plan` (commits `b34fc9e..1bb0af1`; 45/45 tests, tsc clean, builds)
**Staging:** Phase A — implemented in the kokuin working tree, not merged to `main` and not
published. kubun (Phase B, separate repo) adopts the published version; it cannot resolve the
dependency until the owner commits and publishes `@kokuin/oauth`.

## Goal

Extract the generic, RFC-shaped OAuth 2.0 client mechanics that were duplicated across the stack
(kubun's `@kubun/plugin-connector` + `@kubun/credential`; mokei's `@mokei/http-client`) into one
dependency-light leaf package. It owns PKCE, hardened HTTP with structured errors, the
authorization-code and refresh-token exchanges, and a pending-authorization orchestration + store
port — and **no** application concern (no DID/credential wrapping, no connector registry, no MCP
resource discovery, no provider-specific authorization policy). kubun adopts it first; the package is
shaped so mokei's `http-client` can adopt it later.

## What was built (`packages/oauth`)

- **Core types + `OAuthTokenError`.** An `OAuthProviderDefinition` discriminated on `mode`
  (`confidential` | `native` | `broker`), `TokenResponse`, `OAuthErrorCode`, a `RequestOptions`
  (`signal` / `timeoutMs` / `maxBytes`), and an `OAuthTokenError extends Error` carrying `status`,
  parsed `code`, and `description`.
- **PKCE.** `generateCodeVerifier` / `generateState` (32 random bytes → unpadded base64url via the
  runtime's `getRandomValues` + `@sozai/codec` `toB64U`) and `deriveCodeChallenge`
  (`base64url(sha256(utf8(verifier)))`, S256).
- **Hardened HTTP (`fetchOAuthJSON`).** HTTPS-only endpoints (with an `http:` loopback exception),
  `redirect: 'error'`, a caller signal combined with an `AbortSignal.timeout` deadline via
  `AbortSignal.any`, a streamed per-chunk 1 MB size cap, and a non-OK path that parses the OAuth
  error body into a structured `OAuthTokenError`. The HTTPS guard lives in `src/secure-url.ts`,
  shared with the authorization-URL builder.
- **`buildAuthorizationURL`.** Pure. Sets the generic core params (`client_id`, `redirect_uri`,
  `response_type=code`, space-joined `scope`, `state`, `code_challenge`,
  `code_challenge_method=S256`) and merges caller-supplied `authorizationParams`
  (e.g. Google's `access_type=offline`, `prompt=select_account consent`) **without** letting them
  override any protected core field. Rejects a non-HTTPS authorization endpoint.
- **`exchangeCode` / `refreshToken`.** Runtime guards run before any HTTP (non-empty `clientID`;
  `confidential` requires a non-empty `clientSecret`; unknown/missing `mode` rejected — never a
  secretless fallthrough); `client_secret` is sent only when present; `broker` throws
  "not implemented"; the 2xx body is validated (`access_token` non-empty, `token_type` string,
  `expires_in` finite ≥ 0 when present, unknown fields preserved, `{}`/empty rejected) before return.
- **Pending-authorization orchestration + `PendingAuthStore<TExtra>` port.** `startAuthorization`
  (sweep expired, generate state + PKCE, build+validate the URL, create the record) and
  `completeAuthorization` (single-use consume; reject absent/expired/provider-mismatch/redirect-
  mismatch; exchange using the **stored** redirect URI + verifier; return `{ tokens, record }`). Ships
  an in-memory reference store; the record carries an absolute `expiresAt`.

## Key design decisions (rationale preserved)

1. **True leaf, runtime-routed I/O.** Depends only on `@sozai/runtime` (its `fetch` + randomness keep
   the package correct on React Native / expo), `@noble/hashes` (`sha256`), and `@sozai/codec`
   (`toB64U`). No `@kokuin/token`, no kubun/mokei. Timeout / streaming / size-cap are done in-package
   with standard `AbortSignal` APIs, not taken from the runtime.
2. **Three client modes, one discriminated type.** `confidential` holds a real secret sent via
   `client_secret_post`; `native` is a public/installed client where PKCE (not a secret) protects the
   code exchange and refresh is secretless; `broker` is a **type marker only** this version — both
   exchange and refresh throw, and no wire shape / `tokenExchangeURL` / renewal contract is prescribed
   (a real broker needs its own threat model). Only `client_secret_post` is supported; HTTP Basic is
   deferred.
3. **Guards enforced at runtime, not only at compile time.** JS callers and malformed config can
   bypass the discriminated type, so every entry point re-checks before any HTTP and never falls
   through to native behaviour on an unknown mode.
4. **Structured token errors.** Non-OK responses become `OAuthTokenError` so a consumer can tell a
   confirmed `invalid_grant` from a transient failure (non-JSON/empty error body → `code` undefined,
   treated as transient). This preserves the contract kubun's error classification depends on.
5. **`authorizationParams` merged without overriding core.** Provider-specific query params are the
   caller's to pass; the seven security-relevant core params are protected (filtered from the merge
   and re-set unconditionally afterward), so a caller cannot smuggle a `client_id` / `redirect_uri` /
   `response_type` / `code_challenge_method` override.
6. **Absolute `expiresAt` per pending record.** The record stores an absolute deadline set at
   `startAuthorization` (`now + ttlMs`); the sweep and the callback validate against that stored
   deadline. A new short-TTL flow therefore cannot delete other flows' still-valid records, and the
   callback cannot extend or shorten a record's life (`completeAuthorization` takes no `ttlMs`). This
   corrected an adversarial-review finding where a per-call TTL swept the shared store by `createdAt`.
7. **HTTPS enforced on both endpoints.** The token-endpoint guard is shared (`src/secure-url.ts`) and
   also applied to the authorization endpoint, so `state` + the PKCE challenge are never emitted to an
   `http://` authorization URL (loopback `http:` excepted for development).
8. **`TokenStore` cut.** kubun uses its own DID-wrapping credential store; nothing else consumes a
   generic token store yet. Add it when mokei actually adopts.

## Review

Six tasks were each spec-reviewed on the diff; a whole-branch review and an independent Codex
adversarial review followed. Two review-surfaced defects were fixed on the branch: the per-call-TTL
store sweep (decision 6) and the missing authorization-endpoint HTTPS guard (decision 7).

## Follow-on

Two hardening items rooted in the React Native `fetch` transport were deferred — the package cannot
force transport behaviour from a leaf position. See
`next/2026-09-11-oauth-native-transport-hardening.md`.

## Not in scope (this effort)

Broker implementation, discovery (RFC 8414 / RFC 9728), a loopback redirect server,
`client_secret_basic`, and a generic `TokenStore` — all deferred.
