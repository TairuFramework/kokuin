# @kokuin/browser

## Installation

```sh
npm install @kokuin/browser
```

## Requirements

`BrowserKeyStore` holds a non-extractable Ed25519 signing key plus the X25519 agreement key
derived from it, and needs `SubtleCrypto` support for both algorithms: Chrome 137+, Firefox
130+, or Safari 17+. On an older browser it hard-errors rather than falling back to ES256 — a
fallback would mint a different DID for the same keyID.

Key records minted before this requirement (ES256) keep working, but only for signing —
WebCrypto will not let an ECDSA key do `deriveBits`, so a legacy record cannot decrypt. Use
`store.provideSigningIdentity(keyID)` for one; `store.provideIdentity(keyID)` throws on it,
since it promises decryption. Legacy records are never silently re-keyed, since that would
change the identity's DID.
