# @kokuin/expo

## Installation

```sh
npm install @kokuin/expo
```

## Crypto provider migration to 0.5.0

The constructor and `ExpoKeyStore.open(options?)` accept `StoreEntryOptions & { crypto?: CryptoProvider }`.
Identities capture the provider for asynchronous software signing. Omission selects strict `nobleCrypto`.
The store copies entry options and strips `crypto` before SecureStore calls.
Reopening the singleton with a different resolved provider throws, including omission after custom selection.
Same-reference reopen succeeds. Explicit noble and omission agree for a default store.
`provideIdentitySync` remains synchronous. Derivation and agreement retain their existing implementations.

See [provider adoption](../../docs/reference/crypto-provider.md) for selection, migration and verification policy.
