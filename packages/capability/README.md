# @kokuin/capability

## Installation

```sh
npm install @kokuin/capability
```

## Crypto provider migration to 0.6.0

`CreateCapabilityOptions`, `DelegationChainOptions` and `RevocationOptions` gain `crypto?: CryptoProvider`.
`createCapability`, `checkDelegationChain` and `checkCapability` forward it through parent and chain verification.
`createMemoryRevocationBackend` and `createRevocationChecker` capture it at construction.
Revocation checks retain `historic: true`. Capability and revocation creation still sign through the supplied identity.
Existing return contracts remain unchanged. Custom algorithm verifiers own their policy and override provider verification.
The strict default rejects crafted ZIP-215-only signatures on reverification. No historical rescan or version gate is introduced.
Provider operational errors propagate unchanged through refusal paths.

See [provider adoption](../../docs/reference/crypto-provider.md) for selection, migration and verification policy.
