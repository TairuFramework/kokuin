# Restore non-extractable X25519 agreement key in @kokuin/browser once WebKit is fixed

**Priority:** backlog (tracks an upstream WebKit bug; revert when it lands)
**Upstream:** https://bugs.webkit.org/show_bug.cgi?id=312279 — "Non-extractable X25519
CryptoKey stored in IndexedDB returns null on subsequent read in Safari" (NEW, unassigned,
rdar://problem/175258859). 100% reproducible on Safari 26.4 / macOS 15.4, and in Playwright's
bundled WebKit.

## Background

`@kokuin/browser` identities are non-extractable Ed25519 signing + X25519 agreement keys
(`did:key` EdDSA). The design intent (keystore-contract work, see
`completed/2026-07-14-keystore-contract.complete.md`, decision 4) was that IndexedDB holds
**only** non-extractable `CryptoKey`s, so XSS after provisioning cannot exfiltrate key material.

WebKit breaks that for X25519 specifically: storing a record containing an X25519 `CryptoKey`
(extractable **or** non-extractable) in IndexedDB — `put()` reports success, `get()` returns
`null`. So on Safari every page reload minted a fresh identity (new DID), breaking durability.
Confirmed with isolated probes:

- non-extractable Ed25519 `CryptoKey` → persists fine
- non-extractable AES-GCM `CryptoKey` → persists fine
- X25519 `CryptoKey`, extractable or not → `get()` returns `null`

## Interim workaround (shipped)

`BrowserKeyRecord` now stores the X25519 agreement key as raw bytes (`agreementSecret:
Uint8Array`) instead of a `CryptoKey`; the Ed25519 signing key stays a non-extractable
`CryptoKey` (it persists). `createBrowserIdentity` re-imports the agreement `CryptoKey` from
those bytes on read. See `packages/browser/src/utils.ts` (`BrowserKeyRecord`,
`generateKeyRecord`) and `packages/browser/src/identity.ts` (`createBrowserIdentity`).

**Security cost:** `agreementSecret` is the Ed25519 private scalar (`toMontgomerySecret`), so an
attacker who can read IndexedDB (e.g. via XSS) can both decrypt to the identity and forge its
signatures — even though the signing `CryptoKey` itself remains non-extractable. This is a real
regression from the "IndexedDB holds only non-extractable keys" property, accepted as the only
way to have durable identities in Safari while the WebKit bug is open.

## When WebKit is fixed

Revert `agreementSecret: Uint8Array` back to `agreement: CryptoKey` (non-extractable), restore
the two-key non-extractable import in `generateKeyRecord`, drop the re-import in
`createBrowserIdentity`, and re-tighten the `BrowserKeyRecord` docs. The web e2e persistence
tests (`tests/e2e-web/test/durable-reload.spec.ts`, `two-identities.spec.ts`) already assert
DID stability across reload on all three engines, so they guard the revert.
