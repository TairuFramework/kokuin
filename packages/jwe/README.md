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

## Named params migration

| Export | Named params type | Previous positional form |
| --- | --- | --- |
| `createTokenEncrypter` | `CreateTokenEncrypterParams` | `createTokenEncrypter(recipient: Uint8Array, options: EncryptOptions)` |
| `deriveSharedSecretAsync` | `DeriveSharedSecretAsyncParams` | `deriveSharedSecretAsync(recipient: string, options: ResolveRecipientOptions)` |
| `createTokenEncrypterAsync` | `CreateTokenEncrypterAsyncParams` | `createTokenEncrypterAsync(recipient: string, options: ResolveRecipientOptions)` |
| `encryptToken` | `EncryptTokenParams` | `encryptToken(encrypter: TokenEncrypter, plaintext: Uint8Array)` |
| `decryptToken` | `DecryptTokenParams` | `decryptToken(decrypter: KeyAgreementIdentity, jwe: string)` |
| `wrapEnvelope` | `WrapEnvelopeParams` | `wrapEnvelope(mode: EnvelopeMode, payload: Record<string, unknown>, options: WrapOptions)` |
| `unwrapEnvelope` | `UnwrapEnvelopeParams` | `unwrapEnvelope(message: string, options: UnwrapOptions)` |
