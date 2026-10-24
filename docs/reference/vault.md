# Vault

`@kokuin/vault` provides content-key crypto, factor helpers, owner-bound IDs, codecs and five signed vault record definitions.
It depends on token, jwe and records, with no Hozon dependency.
`@kokuin/store-vault` depends on Hozon, records and vault for local storage, optional replicated storage and coordinators.
Consumers supply authority, transport, membership policy and clocks.

## Crypto core

`getSuite(SUITE_VAULT_1)` selects suite number `1`, named `VAULT_1`.
`isSupportedSuite` checks support without throwing.
The suite exposes `generateContentKey`, `wrap`, `unwrap`, `encryptEntry` and `decryptEntry`.
Content keys and derived factor secrets contain 32 bytes.
AES-256-GCM uses a separate 12-byte IV and appends its 16-byte tag to ciphertext.

| Input or domain | Encoding and binding |
| --- | --- |
| DID factor | X25519 agreement, with public descriptor fields `recipient` and base64 `epk` |
| Passphrase or PIN factor | Argon2id, 16-byte random salt, 32-byte output. Descriptor fields: base64 `salt`, `m`, `t`, `p` |
| Default Argon2id cost | `{ m: 19456, t: 2, p: 1 }`. Memory uses KiB |
| Accepted cost bounds | Integer `m`: 8 through 262144, `t`: 1 through 10, `p`: 1 through 16 |
| Wrapping KEK | HKDF-SHA256 over ordered concatenated factor secrets, UTF-8 `wrappingID` salt, 32-byte output |
| Wrapping HKDF info | UTF-8 `kokuin/vault/wrap/v1:${suiteID}:${keyID}:${keyVersion}` |
| Wrapping AAD | UTF-8 canonical JSON of ordered factor descriptors. Object keys sort, array order remains significant |
| Entry AAD | UTF-8 `kokuin/vault/entry/v1:${suiteID}:${keyID}:${keyVersion}:${entryID}` |

A wrapping requires at least one factor. Secret factor kinds cannot repeat.
A PIN requires a DID factor in the same wrapping. A passphrase can stand alone.
`FactorInput` accepts DID recipients or secret bytes. `FactorInputs` supplies passphrase and PIN bytes for opening.
`wrappableDID(identity)` preserves a resolvable long-form DID when available.
Equality checks normalise DIDs without discarding recipient key material needed for agreement.

`createVaultKeyID(owner, unique)` hashes exact owner bytes concatenated with unique bytes using BLAKE3.
Unsigned varints frame namespace `0xb6`, key type `31` and digest length `32`, followed by the digest.
The result uses lowercase base36 multibase with prefix `k`.
`createVaultKeyReference` also returns `keyUnique`, encoded as unpadded base64url.
Signed key metadata requires 16 unique bytes and commits the normalised owner through this ID.
Callers normalise equality DIDs before minting IDs. Entry IDs remain caller-selected, owner-qualified strings.

### Trusted descriptors and failures

`descriptorDigest` hashes length-framed canonical descriptor JSON with BLAKE3 and returns a 32-byte base64url digest.
`unwrap` accepts optional `expectedDescriptorDigest` from trusted local state or independently authenticated metadata.
A mismatch throws `VaultTampered` before factor validation, agreement, Argon2id or decryption.
The `descriptorDigest` carried beside attacker-editable descriptors cannot establish trust by itself.

A wrapping GCM failure throws `VaultSecretRejected` with the original error as `cause`, including DID-only wrappings.
Without a trusted descriptor mismatch, wrong secrets and ciphertext or descriptor corruption can produce the same authentication failure.
Malformed descriptors can independently throw `VaultTampered`. Missing factors throw `NoAvailableFactor`.
Entry GCM failures throw `VaultTampered` with the original cause.

Crypto-only hosts call the suite directly with opaque bytes and their own addresses.
The host owns current-state persistence, journal/outbox atomicity, rollback protection, device binding and export or sync policy.
The host supplies an already available agreement identity when its message path must never prompt.
This path requires no store, coordinator, operation signer or replicated history.

## Local and replicated storage

`vaultStoreDefinition` registers the `vault` store. `getVaultStore(provider)` returns `VaultStoreAPI`.
The base tables are `vault_keys`, `vault_wrappings` and `vault_entries`, under Hozon's configured table prefix.
Addresses require an explicit `ownerDID`. Base storage preserves owner and recipient spellings.
Rows contain public key/version/state metadata, ordered descriptors, IVs and opaque encrypted bytes.
Entry `kind`, `label` and string `attributes` remain public.
Filters combine exact kind/label equality with conjunctive attribute-subset matching, without decryption.

Local key puts accept equal or greater versions. Ordinary entry puts replace bytes without HLC arbitration and refuse key reassociation.
`moveEntry` accepts caller-encrypted destination bytes and preserves the owner-qualified entry ID.
Conditional updates never insert or move rows. HLC CAS returns `updated`, `absent` or `superseded`.
Base storage supplies persistence, with encryption, authorisation and clocks supplied above it.

Optional `vaultRecordsStoreDefinition` depends on the base store and adds decisions, copies, branches, candidates and recipient revocations.
Base registration alone creates none of that replicated state.
Initialisation binds one operation kind permanently to the records database, outside caller transactions and without vault key locks:

```typescript
import {
  createVaultRecords,
  getVaultRecordsStore,
  getVaultStore,
  vaultRecordsStoreDefinition,
  vaultStoreDefinition,
} from '@kokuin/store-vault'
import { VAULT_OP_KIND } from '@kokuin/vault'

// db is a HozonDB with an installed adapter.
db.register(vaultStoreDefinition)
db.register(vaultRecordsStoreDefinition)
await getVaultRecordsStore(db, VAULT_OP_KIND)
const store = await getVaultStore(db)
const records = createVaultRecords({
  store,
  opKind: VAULT_OP_KIND,
  authority,
  validateConsumerMetadata,
  nowMS,
  maxDriftMS,
})
```

`VAULT_OP_KIND` is the exported constant `kokuin/vault-op/v1`. Factories require an explicit `opKind` and never default it.
Signing, apply, embedded proof verification and reconciliation must use the same kind.
Reads and writes refuse an absent or different durable binding.
`getVaultRecordsStore(provider)` without a kind only retrieves storage already initialised by the host.

`records.apply(records, transportContext)` receives signed records through the [records engine](./records.md).
`records.write({ records, preconditions, transportContext })` submits signed local output through the same engine.
Key preconditions compare expected version, including `null` for absence, and an optional complete branch set.
Entry preconditions compare exact HLC, including `null` for absence. Every output needs a covering precondition.
Preconditions and apply share the transaction and key locks.
The exposed adapter's `putCopy` and `pruneCopy` are trusted engine ports requiring an adapter transaction.
Untrusted records enter through apply.

Each logical record address has one storage mode. Local mutation of replicated addresses throws `VaultModeConflict`.
Replicated projections onto local addresses also refuse and roll back the apply transaction.
Entry mode is independent of parent-key mode.
Mode reservations survive signed tombstones, suppressed wrappings and local physical deletion after optional registration.
There is no implicit adoption or unrevocation API.

## Signed record types

`vaultRecordTypes` constructs the five definitions with explicit authority, consumer metadata validation, replay domain and transaction-bound effect ports.
Prechecks validate structure. Consumer callbacks decide authority.
Payload codecs use canonical JSON with binary fields encoded as unpadded base64url.
`decodeVaultRecord` validates live payload structure. Its caller remains responsible for signature and payload-digest verification.

| Type | Address and content | Policy and dependencies |
| --- | --- | --- |
| `vault.key` | ID commits owner and `keyUnique`. Metadata carries version, state and consumer. Live payload carries suite and state | Monotonic `[version, stateRank]`, where active=0, retired=1, deleted=2. Equal ranks report forks. No dependencies |
| `vault.key-branch` | ID is payload digest. Payload embeds introducing key `opJWT`, `opHash`, author, HLC and suite. Metadata names key, version and branch | Immutable. Requires the same owner's key at least at that version. Both embedded introducing op and outer record receive authority checks |
| `vault.wrapping` | Wrapping ID, descriptors, descriptor digest, IV and wrapped key. Metadata names recipient, key/version and exact branch | LWW. Live records require key at least at that version and exact owner/key/version/branch proof. Tombstones require the key |
| `vault.entry` | Entry ID, IV and ciphertext. Metadata names key/version, `contentHLC`, public entry metadata and exact branch | Monotonic content HLC, then key version. Declares key and branch dependencies. Live entries require exact branch evidence |
| `vault.revocation` | ID from `vaultRevocationRecordID(keyID, recipientDID)`. Empty payload, metadata names key and normalised revoked DID | LWW, dependent on key. Tombstones always refuse. Recipient denial remains permanent across versions |

Revocation IDs encode `${keyID.length}:${keyID}/${normalizeDID(recipientDID)}`.
Revocations suppress wrappings naming the denied DID as explicit recipient or DID factor.
Deleting an ordinary wrapping does not create a revocation.
Signed entry tombstones preserve deletion intent across later re-encryption.
Authorised losing entries remain received candidates. Exchange lists selected decisions and their copies, without guaranteeing complete candidate history.

Every type reserves one opaque signed field, `meta.consumer`.
`validateConsumerMetadata(value, request)` must accept it before authority succeeds.
The vault does not interpret grant, capability, member-incarnation, controller or provider evidence inside that value.
Unknown metadata fields outside the defined schema refuse.

### Branch selection

`branchID` is `${introducingHLC}:${introducingOpHash}`, backed by a verified introducing key operation.
`compareVaultBranches` compares introducing claim digest, then op hash. `selectWinningBranch` selects the greatest result.
Opening and repair use this rule rather than comparing branch labels.
Replicated live wrappings and entries require non-empty branch references and exact dependencies.
Ordinary opening refuses an entry on a superseded branch. Explicit repair can open authenticated losing branches.

## Authority and re-endorsement

`CredentialAuthority` exposes `authorize(request): Promise<boolean>`. There is no default authority.
The store-vault contract accepts unsigned coordinator requests and vault's verified record requests.
Every public coordinator operation calls authority, including cached opens, missing entries, listings, repair and re-endorsement.
Refusal throws `VaultNotAuthorized` before persistent writes. Record refusal prevents that record's admission or disclosure.

| Coordinator verb | Operations |
| --- | --- |
| `read` | `openKey`, `unlock`, `lock`, `lockAll`, `status`, `listKeys`, `readEntry`, `getEntry`, `listEntries` |
| `administer` | `createKey`, `setKeyState`, `deleteKey`, `grant`, `addFactor`, `removeFactor`, `rotate`, `repairFork`, `putEntry`, `updateEntry`, `updateEntryIfPresent`, `updateEntryIfUnchanged`, `deleteEntry`, `reKeyEntry`, `reendorse` |

Unsigned requests use `source: 'local'`, even for replicated reads.
They carry mode, operation, verb, owner, principal as issuer, optional key/entry IDs, original request and unchanged `transportContext`.
Their read port exposes key, entry, wrapping and listing queries.
Verified requests use `source: 'record'`, verified op, owner, issuer, record key, record, unchanged context and a transaction-bound records read port.
Record admission uses `administer`. Wrapping receipt additionally uses `read`. Visibility uses `read` for every type.
The record issuer remains the signer. The consumer authenticates the requesting principal through transport context.

`vaultHolderTypes` restricts key-holding proofs to wrappings.
`vaultKeyVersionReader` resolves live owner-qualified key versions.
`vaultProofAuthorizer` reuses admission authority without binding a proof to the local receiving device.

Consumers decide effective membership and removal eligibility. A removed incarnation's own copy no longer authorises new receipt.
An effective member re-signs a stored decision to supply another authorised copy of the same content.
`reendorse({ ownerDID, keyID, records })` verifies named stored copies and re-signs their exact claims through apply.
It preserves payloads and `meta.consumer`, includes named key tombstones, and confines output to the explicitly named owner/key.
Apply retains the replacement before pruning copies whose issuers no longer pass authority.
Stored replays remain no-ops. Re-endorsement discovery and historic authorisation of embedded introducing operations remain consumer policy.

## Coordinators, rotation and repair

`createVaultCoordinator` requires explicit mode, store, principal, agreement identity or `null`, runtime, authority and host `nextHLC`.
Replicated mode additionally requires a signer and records configuration, with optional storage already initialised.
Local mode uses unsigned base storage. Replicated mutations submit all signed output through `write` and apply.
Rejected, parked or losing coordinator output throws `VaultWriteConflict` and rolls back.

`createKey` requires a canonical owner DID. Its default wrapping addresses the agreement identity in resolvable form.
`grant`, `addFactor` and `removeFactor` operate on the current version and refuse a historical `atVersion`.
`setKeyState` and `deleteKey` change lifecycle metadata.
Replicated retirement outranks same-version activation. A refused reactivation produces `VaultWriteConflict`.
Entry operations accept opaque byte plaintext and public metadata, without application-specific IDs.
`reKeyEntry` authorises both keys and re-encrypts while preserving the entry address.

Both `rotate` and `repairFork` require explicit `excludedRecipients` and `reissue` arrays, including empty arrays.
Rotation generates a new content key, increments version, re-wraps retained factors and re-encrypts selected entries.
Exclusions match explicit recipients and DID factors through normalised DID equality.
Replicated exclusions publish permanent revocations. Local exclusions delete matching existing wrappings without maintaining permanent denials.
Retained secret factors require their supplied inputs for re-wrapping.

| Reissue action | Effect |
| --- | --- |
| `preserve` or no instruction | Carry selected plaintext or tombstone and public metadata forward, preserving content intent |
| `replace` | Encrypt supplied new plaintext for a selected live entry |
| `delete` | Delete the local entry or publish a signed tombstone without requiring plaintext |
| `skip` | Leave the old entry untouched |

An instruction names one existing selected entry. Duplicate or unknown instructions refuse the whole operation.
Optional `contentHLC` replaces content intent. Optional `consumer` replaces signed opaque metadata.
Without those fields, re-encryption preserves their previous values.
Replacement of a tombstone is unsupported.

Repair uses authenticated branches, received entry candidates and prior tombstones.
It can rotate when the selected entry projection belongs to a losing branch, even when competing plaintexts agree.
It returns `{ status: 'rotated', version }`, `{ status: 'not-needed' }` or `{ status: 'pending' }`.
Unavailable branch material or preservation factors can leave repair pending for an explicit retry.
Local repair returns not-needed after authority. Reads never initiate repair or removal recovery.
The consumer supplies removal decisions and any reissue policy. Received history has no all-peers completeness guarantee.

## Transactions, locks and reads

Store methods use `withStoreTransaction` to join an enclosing transaction.
Coordinators hold the complete Hozon key-lock set through mutations, including crypto work.
Multi-key operations acquire locks together in Hozon's advisory-ID order. Absent keys receive the same protection.

The records lock `{ type: 'vault.key', key: JSON.stringify([ownerDID, keyID]) }` maps to:

```typescript
withKeyLock(provider, 'vault_keys', [JSON.stringify([ownerDID, keyID])], callback)
```

`lockKeyRow` and `lockKeyRows` require a transaction. Callers declare complete key sets before authoritative multi-key reads.
Coordinators created from the host transaction's store can commit vault changes with journal/outbox writes.
Errors must propagate out of that host transaction to roll everything back.
No statement binds more than 500 parameters. Hosts supply canonical increasing HLCs and any required restart floor.

Generic reads never repair data, acquire write locks or write history.
Replicated `readEntry` uses a joined read transaction and compares projection fields against the selected signed entry.
Checks include HLC, key/version, provenance, kind, label, attributes and the payload digest of encoded IV/ciphertext.
A stale ciphertext replay beneath a newer signed decision throws `VaultTampered` before returning plaintext.
Retained wrapping projections are checked against signed descriptors, recipient, branch and ciphertext before opening or rotation.
Replicated unwrap receives the signed wrapping's trusted descriptor digest. Local rows supply no independent trusted digest.
`getEntry` and `listEntries` return stored public rows rather than authenticating decrypted content.

Records adapter `get` and `getMany` fail closed on unreadable decisions with `VaultRecordRowError`.
`list` omits corrupt decisions and reports them through optional `onCorruptRow`.
Range leaves and fingerprints use the records package's functions over selected decisions.

## Cache and erasure

`createKeyCache` clones buffers on set/get and zeroes retained copies on eviction or lazy expiry.
`DEFAULT_UNLOCK_TTL` is fifteen minutes. The clock and TTL are configurable.
Coordinator cache keys include owner, key ID and version, with branch checked on reuse.
`openKey` returns a private buffer that the caller must erase after use.
`readEntry` returns plaintext owned by the caller.

`unlock` warms the cache. `lock` evicts one owner-qualified key.
`lockAll(ownerDID)` evicts only that owner's cached keys and invalidates that owner's pending cache warming.
Other owners' cached and pending keys remain unaffected. Already returned caller buffers remain caller-owned.
Input-free opens coordinate in-flight work. Supplied secrets verify independently even when a key is cached.
All PIN-bearing coordinator opening paths share an in-memory throttle. `VaultPinRejected` exposes attempts remaining and retry delay.
Coordinator mutation paths erase temporary generated keys, opened keys and internally decrypted plaintext on success and failure.
Revocation and erasure cannot recover plaintext or old keys already retained by another recipient.

## Exported errors

| Package | Names |
| --- | --- |
| `@kokuin/vault` | `VaultError`, `NoAvailableFactor`, `InvalidVaultFactors`, `UnsupportedVaultSuite`, `VaultTampered`, `VaultSecretRejected`, `VaultPinRejected`, `VaultRecordPayloadError` |
| `@kokuin/store-vault` | `VaultModeConflict`, `VaultWriteConflict`, `VaultRecordRowError`, `VaultNotAuthorized`, `VaultNotFound`, `VaultRepairPending`, `VaultSupersededBranch`, `VaultKeyLocked` |

`VaultError.code` distinguishes crypto error categories. Store and codec errors use their exported classes and names.
`VaultRepairPending` reports missing authenticated branch material. `VaultSupersededBranch` reports an entry on a non-selected branch.
`VaultKeyLocked` reports required supplied factors. `VaultNotFound` covers missing keys, entries or authenticated evidence.
Invalid API configuration can also throw standard `TypeError`, `RangeError` or `Error`.
