# @kokuin/token

## Installation

```sh
npm install @kokuin/token
```

## Crypto provider migration to 0.7.0

`CryptoOptions` exports `{ crypto?: CryptoProvider }`.
`createSigningIdentityForDID(params: CreateSigningIdentityForDIDParams)`, `createSigningIdentity(params: CreateSigningIdentityParams)`,
`createFullIdentity(params: CreateFullIdentityParams)` and `randomIdentity(options?)` capture the selected provider.
They retain their synchronous return contracts. `createIdentity(input)` gains `input.crypto?` and remains asynchronous.
`signToken` uses the identity's captured signer without a per-token provider override.

`VerifyTokenOptions` and `VerifySignedPayloadInput` gain `crypto?`.
`getVerifier(params: GetVerifierParams)` appends provider options and retains its return type.
Custom algorithm overrides take precedence and own their policy. Missing overrides use strict `nobleCrypto` by default.
Verification caches isolate provider, verifier and resolution policy. Cross-policy verified objects require reverification.
`isVerifiedToken` indicates prior verification, not acceptance under every policy.
Provider errors propagate unchanged. Strict verification rejects crafted signatures previously accepted only under ZIP-215.
There is no historical rescan or version gate.

See [provider adoption](../../docs/reference/crypto-provider.md) for selection, migration and verification policy.

## Named params migration

| Export | Named params type | Fields |
| --- | --- | --- |
| `new UnresolvableIssuerError` | `UnresolvableIssuerErrorParams` | `message, options?` |
| `new IssuerKeyNotFoundError` | `IssuerKeyNotFoundErrorParams` | `message, options?` |

These signature and typing changes preserve cryptographic results, error causes, ordering and storage behaviour.

Additional APIs use the same flat params convention.

| Export | Named params type | Previous positional form |
| --- | --- | --- |
| `getDID` | `GetDIDParams` | `getDID(codec: Uint8Array, publicKey: Uint8Array)` |
| `createFullIdentity` | `CreateFullIdentityParams` | `createFullIdentity(privateKey: Uint8Array, options: CryptoOptions = {})` |
| `createKeyAgreementIdentityForDID` | `CreateKeyAgreementIdentityForDIDParams` | `createKeyAgreementIdentityForDID(id: DIDString, x25519PrivateKey: Uint8Array)` |
| `createSigningIdentity` | `CreateSigningIdentityParams` | `createSigningIdentity(privateKey: Uint8Array, options: CryptoOptions = {})` |
| `createSigningIdentityForDID` | `CreateSigningIdentityForDIDParams` | `createSigningIdentityForDID(id: DIDString, privateKey: Uint8Array, options: CryptoOptions = {})` |
| `findMethodResolver` | `FindMethodResolverParams` | `findMethodResolver(registry: MethodRegistry, did: string)` |
| `verifyMultihash` | `VerifyMultihashParams` | `verifyMultihash(multihash: Uint8Array, bytes: Uint8Array)` |
| `decodePeer4` | `DecodePeer4Params` | `decodePeer4(longForm: string, options: DecodePeer4Options = {})` |
| `assertTimeClaimsValid` | `AssertTimeClaimsValidParams` | `assertTimeClaimsValid(payload: TimeClaimsPayload, options: TimeValidationOptions = {})` |
| `createUnsignedToken` | `CreateUnsignedTokenParams` | `createUnsignedToken(payload: Payload, header?: Header)` |
| `signToken` | `SignTokenParams` | `signToken(signer: SigningIdentity, token: Token<Payload, Header>)` |
| `verifyToken` | `VerifyTokenParams` | `verifyToken(params: VerifyTokenParams)` |
| `concatBytes` | `ConcatBytesParams` | `concatBytes(a: Uint8Array, b: Uint8Array)` |
| `getVerifier` | `GetVerifierParams` | `getVerifier(algorithm: SignatureAlgorithm, verifiers: Verifiers = {}, options: CryptoOptions = {})` |

| API | Named params type | Previous positional form |
| --- | --- | --- |
| `SigningIdentity.signToken` | `SigningIdentitySignTokenParams` | `signToken(payload, options?)` |
| `MultiKeyIdentity.signToken` | `MultiKeyIdentitySignTokenParams` | `signToken(payload, options?)` |
| `KeyAgreementIdentity.agreeKey` | `KeyAgreementIdentityAgreeKeyParams` | `agreeKey(ephemeralPublicKey)` |
| `MultiKeyIdentity.agreeKey` | `MultiKeyIdentityAgreeKeyParams` | `agreeKey(ephemeralPublicKey, kid?)` |
| `DIDCache.set` | `DIDCacheSetParams` | `set(shortForm, doc)` |

Method and callback contracts follow the same convention.

| API | Named params type | Previous form |
| --- | --- | --- |
| `DIDMethodResolver.resolve` | `DIDMethodResolverResolveParams` | `resolve(did, header)` |
| `DIDMethodResolver.resolveHistoric` | `DIDMethodResolverResolveHistoricParams` | `resolveHistoric(did, header)` |
| `DIDMethodResolver.resolveMember` | `DIDMethodResolverResolveMemberParams` | `resolveMember(subject, member)` |
| `DIDMethodResolver.resolveMemberHistoric` | `DIDMethodResolverResolveMemberHistoricParams` | `resolveMemberHistoric(subject, member)` |
| `Verifier` | `VerifierParams` | `verifier(signature, message, publicKey)` |
