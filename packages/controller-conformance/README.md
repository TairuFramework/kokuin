# @kokuin/controller-conformance

Private, framework-independent controller conformance contract. This package is not published.

## Asynchronous implementation contract

Seven `ControllerImplementation` members now return Promises:
`createInception`, `createRotate`, `createReset`, `foldLog`, `resolveBranches`, `createEpochEvent` and `signEvent`.
Implementations and local fixture builders must await these results.
`didFromInception`, `enumerateProfiles`, `digestOf` and derivation helpers remain synchronous.
The contract does not import controller or add provider options to its adapter signatures.
Adapters can capture a provider when binding implementation functions.

## Named params migration

| Export | Named params type | Fields |
| --- | --- | --- |
| `ControllerImplementation.createRotate` | `CreateRotateParams` | `seed, profile, did, prior, snapshot` |
| `ControllerImplementation.createReset` | `CreateResetParams` | `seed, profile, gen, snapshot?` |
| `ControllerImplementation.authorityPrivateKey` | `AuthorityPrivateKeyParams` | `seed, profile, gen, seq` |

The implementation harness receives named objects for rotate, reset and authority-key derivation callbacks.

These signature and typing changes preserve cryptographic results, error causes, ordering and storage behaviour.
