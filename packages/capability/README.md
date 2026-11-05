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

## Named params migration

| Export | Named params type | Fields |
| --- | --- | --- |
| `createCapability` | `CreateCapabilityParams` | `signer, payload, header?, crypto?` |
| `new TokenRevokedError` | `TokenRevokedErrorParams` | `jti, options?` |

These signature and typing changes preserve cryptographic results, error causes, ordering and storage behaviour.

Additional APIs use the same flat params convention.

| Export | Named params type | Previous positional form |
| --- | --- | --- |
| `assertValidDelegation` | `AssertValidDelegationParams` | `assertValidDelegation(from: CapabilityPayload, to: CapabilityPayload, atTime?: number)` |
| `checkCapability` | `CheckCapabilityParams` | `checkCapability(permission: Permission, payload: SignedPayload, inputOptions?: DelegationChainOptions)` |
| `checkDelegationChain` | `CheckDelegationChainParams` | `checkDelegationChain(payload: CapabilityPayload, capabilities: Array<string>, inputOptions?: DelegationChainOptions)` |
| `assertMemberRoot` | `AssertMemberRootParams` | `assertMemberRoot(payload: CapabilityPayload, options: DelegationChainOptions \| undefined, time: number)` |
| `hasPartsMatch` | `HasPartsMatchParams` | `hasPartsMatch(expected: string, actual: string)` |
| `hasPermission` | `HasPermissionParams` | `hasPermission(expected: Permission, granted: Permission)` |
| `isMatch` | `IsMatchParams` | `isMatch(expected: string, actual: string)` |
| `createRevocationChecker` | `CreateRevocationCheckerParams` | `createRevocationChecker(params: CreateRevocationCheckerParams)` |
| `createRevocationRecord` | `CreateRevocationRecordParams` | `createRevocationRecord(signer: SigningIdentity, jti: string)` |
| `assertDeviceCapabilityPolicy` | `AssertDeviceCapabilityPolicyParams` | `assertDeviceCapabilityPolicy(payload: { exp?: number }, options: DeviceCapabilityPolicyOptions = {})` |
| `assertNonExpired` | `AssertNonExpiredParams` | `assertNonExpired(payload: { exp?: number }, atTime?: number)` |
| `assertValidIssuedAt` | `AssertValidIssuedAtParams` | `assertValidIssuedAt(payload: { iat?: number }, atTime?: number)` |
| `assertValidNotBefore` | `AssertValidNotBeforeParams` | `assertValidNotBefore(payload: { nbf?: number }, atTime?: number)` |

Method and callback contracts follow the same convention.

| API | Named params type | Previous form |
| --- | --- | --- |
| `RevocationBackend.get` | `RevocationBackendGetParams` | `get(jti, issuer)` |
| `VerifyTokenHook` | `VerifyTokenHookParams` | `VerifyTokenHook(token, raw)` |

Existing params objects also flatten their options fields:

| Existing params type | Updated params type | Field migration |
| --- | --- | --- |
| `CreateCapabilityParams` | `CreateCapabilityParams` | `Nested options fields → top-level fields` |
