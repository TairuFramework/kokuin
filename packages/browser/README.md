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

## Verification alignment to 0.3.0

This release joins the coordinated strict-token cutover. Browser identity construction and WebCrypto signing retain their existing contracts.
Browser constructors gain no crypto option. Verification selects providers through token, capability or controller options.
Reverification rejects crafted ZIP-215-only signatures under the default policy. No historical rescan or version gate is introduced.

See [provider adoption](../../docs/reference/crypto-provider.md) for selection, migration and verification policy.

## Named params migration

| Export | Named params type | Fields |
| --- | --- | --- |
| `new BrowserKeyStore` | `BrowserKeyStoreConstructorParams` | `getStore` |

These signature and typing changes preserve cryptographic results, error causes, ordering and storage behaviour.
