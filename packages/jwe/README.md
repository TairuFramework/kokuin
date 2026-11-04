# @kokuin/jwe

## Installation

```sh
npm install @kokuin/jwe
```

## Crypto provider migration to 0.2.0

`UnwrapOptions` gains `crypto?: CryptoProvider` for `unwrapEnvelope`.
Signed verification forwards it through JWS, JWS-in-JWE and JWE-in-JWS modes.
`WrapOptions` remains signer-driven. Identity signing, encryption and key agreement retain their existing contracts.
Custom algorithm verifiers own their policy and take precedence over the selected provider.
Strict default verification rejects crafted ZIP-215-only signatures on reverification, without a historical rescan or version gate.
Provider operational errors reject without dynamic fallback.

See [provider adoption](../../docs/reference/crypto-provider.md) for selection, migration and verification policy.
