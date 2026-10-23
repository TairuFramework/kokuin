# Records

`@kokuin/records` provides signed records, merge policies, transactional apply, visibility rules, and range reconciliation.
Payloads remain opaque bytes. Callers supply record types, authorization, persistence, clocks, and transport.
The package has no Hozon dependency.

## Records and ops

A `RecordKey` addresses `(type, owner, id)`. Owners use normalised DIDs.
A `SignedRecord` contains indexed `type`, `owner`, `id`, and `hlc` fields, a payload, `opJWT`, and `opHash`.
A tombstone has no payload.

A `RecordClaim` signs those indexed fields plus `payloadDigest`, `deleted`, and `meta`.
Metadata must survive JSON encoding unchanged. Claims reject extra fields, negative zero, and ids exceeding 1024 UTF-16 units.
`canonicalRecordClaim` sorts object keys recursively and preserves array order.
`recordPayloadDigest` hashes exact payload bytes with BLAKE3, returning a 32-byte base64url digest or `null` for an absent payload.

```typescript
import { signRecordOp, verifySignedRecord } from '@kokuin/records'

const opKind = 'example/record-op'
const signed = await signRecordOp(identity, claim, opKind)
const record = {
  type: claim.type,
  owner: claim.owner,
  id: claim.id,
  hlc: claim.hlc,
  payload,
  ...signed,
}
const verified = await verifySignedRecord(record, opKind, methods)
```

The token envelope contains exactly `iss`, `kind`, and the base64url canonical claim bytes.
Signing uses EdDSA and embeds the long-form identity where required.
`opHash` hashes the length-prefixed exact token string. Verification rejects alternative compact-token spellings and non-canonical claims.
`verifySignedRecord` also checks the indexed fields and `opHash` against the verified token.
It leaves payload verification to `recordPayloadMatches`.

### Replay domain

`opKind` is required when signing or verifying. It has no default.
A signature under one kind cannot verify under another.
`verifyRecordOp`, `verifySignedRecord`, and `recordDecisionDigest` take it before the optional method registry.
Apply and visibility contexts carry one required `opKind`, which their internal checks reuse for stored copies, dependencies, and holder proofs.

WARNING: choose distinct kinds for distinct protocols. Reusing a kind permits replay between protocols sharing the claim shape.
The verified issuer identifies the signer. The claim's owner remains an assertion until authorization succeeds.

### Content decisions and signed copies

A `RecordDecision` contains a key, `decisionHLC`, `contentDigest`, and signed copies of that content.
`recordClaimDigest` hashes the canonical claim, replacing its `hlc` with string `meta.version` when present.
This keeps a versioned content decision stable across signing stamps and signers.
`recordDecisionDigest(record, opKind, methods)` verifies first, then returns that content digest.

`recordDecisionFromVerifiedCopies` selects the greatest canonical decision stamp, then the greatest content digest.
Its explicit stamp source selects claim `hlc` or metadata `version`.
It retains copies matching the selected decision and assumes its inputs have already verified.

## Merge policies

`compareRecordOps` compares verified ops for one record. Identical `opHash` values produce a no-op.
Invalid incoming versions are rejected. Invalid stored versions yield to valid incoming versions.

| Policy | Ordering | Equal-version decision |
| ------ | -------- | ---------------------- |
| `lww` | Complete canonical HLC, including counter and node ID | Greater content digest wins |
| `monotonic` | Lexicographic finite numeric tuple, or canonical `meta.version` HLC with `versionOrder: 'hlc'` | Symmetric `onEqual` hook, otherwise greater content digest wins |
| `immutable` | Conflicting content under one id | Greater content digest wins and reports a conflict |

A numeric tuple extending an equal prefix sorts later. Tombstones follow the same policy as live writes.
Monotonic equal-version conflicts and immutable conflicts report both op hashes.
`onEqual` returns `resolve` or `fork` and must answer identically for both argument orders.

Apply stores one current content decision even when `onEqual` returns `fork`.
The greater content digest remains current. A type retains additional branch evidence through its hooks.

## Apply engine

`applyRecordChunk` receives records, a store adapter, a type registry, `opKind`, clock bounds, resolvers, and optional transport context.
The caller chooses chunk sizes and retains returned parked records for later attempts.

Checks run in this order:

1. Canonical HLC and future drift bound.
2. Registered type and signature under `opKind`, including indexed-field binding.
3. Stateless `precheck`.
4. Exact dependencies.
5. Owner continuity and `authorize`.
6. Merge policy.
7. Payload digest before storing a winning op.

`dependsOn` orders record types. Cyclic or unregistered dependencies throw `RecordTypeGraphError`.
`dependencies` reads the verified claim and returns owner-qualified keys with optional `satisfiedBy` predicates.
Missing or unsatisfied dependencies park records. Apply retries them after a pass stores something.
A pass with no progress returns the remaining parked records.

Each chunk runs transactionally. Replayed stored copies remain no-ops, including when their precheck or authorization would now refuse them.
Same-decision copies can add another signing key. Apply stores a replacement before pruning copies whose issuers no longer pass authorization.
Stored records advance `receiveClock` after the chunk's transaction returns. An owned transaction has committed at that point.
Inside a caller-owned transaction, apply advances `receiveClock` before the enclosing transaction commits.
Callers needing commit-only clock effects must defer them until that commit.
Rejected, parked, and losing records leave it unchanged.

### Locks and errors

`lockKeys` derives speculative affected keys from incoming records and stored decisions.
Apply deduplicates and sorts them, acquires transaction locks together, then rechecks the lock set under those locks.
A change retries an owned transaction, up to five attempts, then throws `RecordSourceChangedError`.
An adapter marked `isTransaction` propagates this error immediately so the enclosing transaction can roll back.

Store, resolver, and ordinary hook errors roll back the chunk and propagate.
`RecordContentRefusalError` identifies a permanent content refusal.
With an owned transaction, apply rolls back, excludes that record, and retries the remaining chunk.
Within a caller-owned transaction, the refusal propagates to the caller.

### Hooks

`afterApply(record, store)` runs inside the transaction after a winning content decision is stored.
Adding another signed copy of the same decision does not run `afterApply`.
`afterAuthorize(record, store)` runs after authorization and payload verification, including for an op that subsequently loses the merge.
It can retain authenticated branch evidence. Stored replays bypass both hooks.

## Store adapter

`RecordStoreAdapter` supplies persistence without requiring a database library.
One store holds ops of exactly one `opKind`. All records enter through apply, which verifies them under that kind.
Never share a store, or reconcile two stores, across kinds.
`rangeLeaf` and decision digests assume records already verified under the store's kind.
These comparison values do not isolate replay domains themselves.

| Member | Contract |
| ------ | -------- |
| `get(key)` | Current owner-qualified decision or `null`, including tombstones |
| `getMany?(keys)` | Same answers and errors as `get`, keyed by `recordKeyText`, with missing decisions omitted |
| `list(types)` | Current decisions for the requested types, including tombstones |
| `putCopy(record)` | Retain an authorized copy of the winning decision, replacing prior content when the decision changes |
| `pruneCopy(key, signerDID)` | Remove a signer's copies after a replacement is held |
| `transaction(fn)` | Supply a transaction-bound adapter, commit on success, and roll back on errors |
| `isTransaction?` | Identify an adapter already bound to a caller-owned transaction |
| `lock?(keys)` | Acquire transaction-scoped locks together before authoritative reads |
| `adapterForType?(type)` | Optional routing to another adapter |
| `listByGroup?(type, groupID)` | Optional indexed lookup by a group named in signed metadata |

The store retains one authorized copy per signing key. Distinct keys for one issuer remain distinct holders.
`getRecordDecisions` deduplicates keys and uses `getMany` when available, falling back to individual reads.
A type returning lock keys requires an adapter with `lock`.
Adapters bound to an enclosing transaction join it and set `isTransaction: true`.

## Authorization and transport context

A `RecordTypeDefinition` supplies `type`, `policy`, `dependsOn`, `dependencies`, and `authorize`.
Optional hooks provide stateless checks, visibility, equal-version decisions, locks, and effects inside the transaction.
`authorize(op, ctx)` receives the verified issuer and claim, incoming record, verified stored record or `null`, transaction store, and caller resolvers.

WARNING: verify payload bytes with `recordPayloadMatches` before an authorizer reads them. Authorization runs before the engine's final digest check.
Related-record reads use `ctx.store`, which contains the current transaction's writes.
Apply enforces owner continuity for `lww` and `monotonic` even with a permissive authorizer.

WARNING: bind `claim.owner` to the owner of the record an immutable record depends on.
Checking only that the issuer matches `claim.owner` can admit a dependent under the wrong owner.
Owner-qualified keys keep different owners' records separate, so this is a dependency-owner authorization risk.
The immutable policy deliberately skips the engine's owner-continuity check.

`RecordReceiveContext` contains only optional `transportContext: unknown`.
Apply passes this value unchanged to every authorizer, including checks of prior copies.
`VisibilityContext` exposes the same opaque field to visibility hooks.
Callers interpret and validate its shape. The engine supplies no transport-specific defaults.
This value never enters a claim, token envelope, digest, or range fingerprint.

## Visibility and holder proofs

`filterVisibleRecords` preserves input order and calls each registered type's `visibleTo` hook.
Types without that hook, and unregistered types, disclose nothing.
`visibilityRules(rules)` builds a hook using any matching rule. Empty rules admit nobody.
`visibleTo` verifies the guarded record under the context's required `opKind` before reading signed metadata.

| Rule | Admission |
| ---- | --------- |
| `ownerDevices` | Requester peer or controller matches the owner |
| `recipient` | Signed `meta.recipient` matches the requester peer |
| `keyHolder` | A verified holding proves access to this owner's named key at the current version |
| `sharedWith` | Signed DID targets match the peer or controller, or `isGroupMember` accepts a signed group target |

`isGroupMember(groupID, did)` resolves share targets independently of the transport carrying a request.
Malformed metadata satisfies no rule.
`currentKeyVersion(owner, keyID)` scopes a key id to its owner.
Only registered `holderTypes` count as holdings.

`verifyHolderProof` checks the signature, indexed fields, payload digest, recipient, key version, stored decision, dependencies, and `authorizeProof`.
Proofs must be live and cannot lose against the responder's stored decision.
A responder behind the requester can accept a newer proof.
Callers bind `authorizeProof` to the same authorization policy and responder store used for ordinary apply.
Proof errors earn no access. Proofs are never stored or forwarded.

Visibility limits disclosure of record existence and metadata. Encryption protects payload secrecy, and receivers still run every apply check.
Ordinary visibility resolver and store errors propagate. Hostile holder-proof errors resolve to refusal.

## Range reconciliation

Responders filter records before computing summaries, splitting ranges, listing leaves, or answering fetches.
Hidden records therefore affect none of these responses.
`rangeLeaf` derives ordering and a sorted signing-key set from a stored decision.
It assumes stored copies were verified. It does not verify signatures itself.

A range is scoped to one type, with a lower exclusive and upper inclusive owner-qualified position.
`fingerprintRange` hashes the sum of eight 32-bit leaf-hash lanes followed by the leaf count.
Fingerprints ignore leaf order and include the content digest and held signer set through each leaf hash.
They are comparison hints, not an authorization or integrity boundary.

`beginRecordPull` starts one directional pass. `advanceRecordPull` processes summaries and leaf lists.
Requester replies contain `matches`, `differs`, or `empty`, or fetch keys already disclosed by the responder.
Differing ranges split into up to 16 summaries. Ranges containing at most 16 leaves can be listed.
An empty requester receives visible records directly.

Leaf lists request missing decisions, later decisions, greater equal-order content digests, or changed signer sets for identical content.
A requester-only record causes no fetch in this direction. The reverse pass handles the other direction.
Fetched records still require `applyRecordChunk` with the same `opKind` and authorization policy.
