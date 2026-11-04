# @kokuin/vault

Database-free content keys, ordered factor wrapping, and authenticated encryption of opaque bytes.

```ts
import { getSuite, SUITE_VAULT_1, wrappableDID } from '@kokuin/vault'
import { createRuntime } from '@sozai/runtime'

const runtime = createRuntime()
const suite = getSuite(SUITE_VAULT_1)
const keyID = 'host-content-key'
const keyVersion = 1
const wrappingID = 'device-wrapping'
const contentKey = suite.generateContentKey(runtime)
const wrapped = await suite.wrap({
  runtime,
  keyID,
  keyVersion,
  wrappingID,
  contentKey,
  factors: [{ kind: 'did', recipientDID: wrappableDID(deviceIdentity) }],
})

// Keep this digest in trusted local state or independently authenticated metadata.
const trustedDigest = wrapped.descriptorDigest
const openedKey = await suite.unwrap({
  ...wrapped,
  keyID,
  keyVersion,
  wrappingID,
  identity: deviceIdentity,
  expectedDescriptorDigest: trustedDigest,
})
const entryID = 'current-state'
const encrypted = suite.encryptEntry({
  runtime,
  keyID,
  keyVersion,
  entryID,
  contentKey: openedKey,
  plaintext: hostBytes,
})
const recovered = suite.decryptEntry({
  ...encrypted,
  keyID,
  keyVersion,
  entryID,
  contentKey: openedKey,
})
```

`deviceIdentity` supplies an already available agreement key. The host must ensure `agreeKey` never prompts on its message path.
The host owns persistence and atomically replaces the current ciphertext with its journal or outbox transaction.
The host also owns device binding, rollback protection, and refusal to sync, export, or retain historical MLS state.

`VAULT_1` uses X25519 agreement, HKDF-SHA256, Argon2id, and AES-256-GCM.
Descriptors preserve factor order. A PIN requires a DID factor in the same wrapping.
The default Argon2id cost is `{ m: 19456, t: 2, p: 1 }`, with memory measured in KiB.
IVs are 12 bytes. Encrypted values contain ciphertext followed by the 16-byte authentication tag.
Entry AAD binds the suite, key ID, version, and entry ID.

`expectedDescriptorDigest` is optional. A trusted mismatch throws `VaultTampered` before agreement, KDF work, or decryption.
The `descriptorDigest` carried beside a presented wrapping is informational and cannot establish trust by itself.
GCM unwrap failures throw `VaultSecretRejected` with the original failure as `cause`, including for DID-only wrappings.
Missing factors and malformed descriptors retain their distinct validation errors.
Entry authentication failures throw `VaultTampered` with the original cause.

`createVaultKeyID(owner, unique)` hashes the exact owner bytes concatenated with unique bytes using BLAKE3.
Its base36 multibase encoding frames unsigned varints for namespace `0xb6`, key type `31`, and digest length `32`.
Callers normalise owner DIDs before minting IDs used as equality keys.
Recipient DIDs retain their resolvable long form. `wrappableDID` selects that form when available.

The package also exports the public key, wrapping, entry-set and descriptor digest helpers,
pure factor reconstruction and eligibility checks, a cloning TTL key cache, and an optional in-memory PIN throttle.

## Crypto provider migration to 0.2.0

All functions below accept appended `options?: CryptoOptions` and now require `await`.

| Export | Result |
| --- | --- |
| `digestParts(parts, options?)` | `Promise<string>` |
| `vaultKeyDigest(key, options?)` | `Promise<string>` |
| `vaultWrappingDigest(wrapping, options?)` | `Promise<string>` |
| `vaultEntriesDigest(entries, options?)` | `Promise<string>` |
| `vaultEntryDigest(entry, options?)` | `Promise<string>` |
| `descriptorDigest(descriptors, options?)` | `Promise<string>` |
| `createVaultKeyID(owner, unique, options?)` | `Promise<string>` |
| `createVaultKeyReference(owner, unique, options?)` | `Promise<{ keyID: string; keyUnique: string }>` |
| `vaultRecordMeta(type, claim, options?)` | `Promise<VaultRecordMetas[Type] \| null>` |
| `decodeVaultRecord(record, recordMeta, options?)` | `Promise<DecodedVaultRecord>` |

`checkDescriptorDigest({ descriptors, expectedDescriptorDigest, crypto? })` now returns `Promise<void>`.
`VaultRecordTypeParams`, `WrapParams` and `UnwrapParams` gain `crypto?`.
`vaultRecordTypes` and `vaultProofAuthorizer` capture provider options at construction.
`vaultKeyVersionReader(store, { opKind, methods?, crypto? })` captures the provider and returns its existing asynchronous callback.
`vaultHolderTypes(types)`, `getSuite`, wrapping and unwrapping retain their return contracts.

Public metadata validation still checks owner/key-ID commitments. Internal structural parsing does not replace that validation boundary.
`compareVaultBranches` and `selectWinningBranch` remain synchronous and consume verified `contentDigest` values.
Canonical IDs, digests and encrypted formats remain unchanged. Provider errors propagate through decoding and authorisation.
SHA-256, X25519, HKDF, AES-GCM, BIP39 and randomness retain their existing implementations.

```ts
const { keyID, keyUnique } = await createVaultKeyReference(ownerDID, unique, { crypto })
const meta = await vaultRecordMeta('vault.key', claim, { crypto })
const decoded = await decodeVaultRecord(record, recordMeta, { crypto })
await checkDescriptorDigest({ descriptors, expectedDescriptorDigest, crypto })
```

See [provider adoption](../../docs/reference/crypto-provider.md) for selection and strict verification.

## Named params migration

| Export | Named params type | Fields |
| --- | --- | --- |
| `new VaultError` | `VaultErrorParams` | `message, options` |
| `new NoAvailableFactor` | `NoAvailableFactorParams` | `kind` |
| `new InvalidVaultFactors` | `InvalidVaultFactorsParams` | `reason` |
| `new UnsupportedVaultSuite` | `UnsupportedVaultSuiteParams` | `suite` |
| `new VaultTampered` | `VaultTamperedParams` | `message, options?` |
| `new VaultSecretRejected` | `VaultSecretRejectedParams` | `kinds, options?` |
| `new VaultPinRejected` | `VaultPinRejectedParams` | `keyID, options` |
| `KeyCache.set` | `KeyCacheSetParams` | `keyID, contentKey, keyVersion, branchID` |

`VaultRecordPayloadErrorParams` names the existing constructor object without changing its fields.

These signature and typing changes preserve cryptographic results, error causes, ordering and storage behaviour.
