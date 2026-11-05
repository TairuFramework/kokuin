# @kokuin/deterministic

## Installation

```sh
npm install @kokuin/deterministic
```

## Crypto provider migration to 0.3.0

`HDKeyStoreParams` gains `crypto?: CryptoProvider`.
`HDKeyStore.fromSeed({ seed, basePath?, crypto? })` and `HDKeyStore.fromMnemonic({ mnemonic, basePath?, crypto? })` accept `crypto?` alongside `basePath?`.
Constructors and factories remain synchronous. Returned identities capture the provider for asynchronous software signing.
Omission selects strict `nobleCrypto`. Seed derivation, mnemonic handling and key agreement retain their existing implementations.

See [provider adoption](../../docs/reference/crypto-provider.md) for selection, migration and verification policy.

## Named params migration

| Export | Named params type | Previous positional form |
| --- | --- | --- |
| `derivePrivateKey` | `DerivePrivateKeyParams` | `derivePrivateKey(seed: Uint8Array, path: string)` |
| `resolveDerivationPath` | `ResolveDerivationPathParams` | `resolveDerivationPath(keyID: string, basePath: string = DEFAULT_BASE_PATH)` |

| API | Named params type | Previous positional form |
| --- | --- | --- |
| `HDKeyStore.fromSeed` | `HDKeyStoreFromSeedParams` | `fromSeed(seed, options?)` |
| `HDKeyStore.fromMnemonic` | `HDKeyStoreFromMnemonicParams` | `fromMnemonic(mnemonic, options?)` |
