# @kokuin/deterministic

## Installation

```sh
npm install @kokuin/deterministic
```

## Crypto provider migration to 0.3.0

`HDKeyStoreParams` gains `crypto?: CryptoProvider`.
`HDKeyStore.fromSeed(seed, options?)` and `HDKeyStore.fromMnemonic(mnemonic, options?)` accept `crypto?` alongside `basePath?`.
Constructors and factories remain synchronous. Returned identities capture the provider for asynchronous software signing.
Omission selects strict `nobleCrypto`. Seed derivation, mnemonic handling and key agreement retain their existing implementations.

See [provider adoption](../../docs/reference/crypto-provider.md) for selection, migration and verification policy.
