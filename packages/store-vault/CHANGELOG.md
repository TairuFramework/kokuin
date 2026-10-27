# @kokuin/store-vault

## 0.2.1

### Patch Changes

- `repairFork` no longer rotates only because a `preserve` reissue instruction supplies fresh `consumer` evidence. When the repair is otherwise not needed it returns `not-needed` without writing; when it is needed, the evidence is signed into that entry's reissued output. `contentHLC` overrides and the other reissue actions keep their behaviour.

## 0.2.0

### Minor Changes

- Add coordinator capabilities for consumers that keep their own authority policy:

  - `refreshEntry` re-encrypts a stored entry at the current key version while preserving its authenticated content intent and public metadata, under entry, key and branch preconditions. It never inserts or resurrects an entry.
  - `refreshWrapping` re-signs an existing live wrapping with newer evidence, keeping its ID, ciphertext, descriptors and recipient, without opening the key. It returns the accepted signed copy.
  - `rotate({ sourceVersion })` rotates from a named older, openable version when current-version material is incomplete. Permanent revocations and exclusions still apply; a rotation that would retain no wrappings is refused.
  - An optional `authorizeEquivalentBranch` port lets `readEntry` decrypt an entry on a losing branch when the consumer explicitly approves the authenticated branches. Without it, `VaultSupersededBranch` is unchanged.

  Rotation now authenticates every supplied secret against the wrapping it recreates, so a wrong PIN can no longer silently change a retained PIN wrapping.

## 0.1.1

### Patch Changes

- Accept optional current-call `consumer` evidence on every coordinator mutation that signs records: `grant`, `rotate` and `repairFork` (key, branch, retained wrapping and revocation records), `setKeyState`, `deleteKey`, `addFactor`, `removeFactor`, the entry update methods, `deleteEntry` and `reKeyEntry`. Leaving it unset keeps the previous behaviour (inherit the prior record's evidence, else `null`); `null` clears it. Supplied evidence passes consumer metadata validation and authority before any write. `reendorse` keeps exact stored claims.

## 0.1.0

### Patch Changes

- Updated dependencies:
  - @kokuin/records@0.2.0
