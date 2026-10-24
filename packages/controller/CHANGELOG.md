# @kokuin/controller

## 0.2.4

### Patch Changes

- Root snapshots carry removed incarnations as tombstones in a new `u` field beside `m`/`d` (a previous verifier ignores it and sees them as absent); `snapshotOf` keeps removed members unless dropped. A reset must not carry `u` (`RESET_HAS_TOMBSTONES`). New `resolveMemberHistoric(did, { did, add, gen })`: resolves an incarnation that was effective in the current generation, including after removal and a later deny of a removed member; refuses another generation, an unknown incarnation and a denied live member (`MEMBER_NOT_HISTORIC`). Controller resolvers return each deny entry raw plus its canonical form, so a `did:peer:4` denied in long form is also denied in short form. `resolveMemberHistoric` now always returns a `removed` flag that is false only when the incarnation is present and effective in the head, and true for every other resolving answer, including pruned entries.

  `KeyState.members` keeps its 0.2 behaviour: chain states hold only live snapshot members, and the head also holds epoch removals. Snapshot tombstones live separately in the new `KeyState.tombstones?: ReadonlyMap<string, MemberEntry>`, keyed by add digest. The head carries the last chain state's tombstones.

  The epoch fold also keeps its 0.2 behaviour: snapshot tombstones never enter causal membership. Root renewal/removal of a tombstoned add refuses because the target is not a member. Tombstoned signers refuse because they are not members. A live member may revoke a tombstoned incarnation's DID without invalidating its historic evidence. The fold always supplies `tombstones`. Readers treat an omitted map on caller-built states as empty. `createReset` silently drops `snapshot.removed`, allowing a reset built from `snapshotOf(head)` after removal. The reset never carries `u`, and the fold retains `RESET_HAS_TOMBSTONES`.

  Logs written by this version fold on 0.2.3 to the same members, deny sets and epoch effects: 0.2.3 ignores `u`. Only inputs that kokuin's builders never emit from honest state are newly refused: a reset carrying `u` (`RESET_HAS_TOMBSTONES`), a reset whose `g` is not a safe integer, and a malformed `u` (an add duplicated across `m` and `u` or within `u`, a non-array, a negative lease, a non-EdDSA or root-key pin, or a DID that does not carry its pin).

## 0.2.3

### Patch Changes

- Add `deviceRevokeIndices(did, chain, subject)`: every same-generation rotate that newly denies the subject, folded once. A verifier checking a specific rotate, or applying its own generation floor, uses it instead of the first index, so a re-revoke after a reset is found.

## 0.2.2

### Patch Changes

- Export `deviceRevokeIndex` to find the first same-generation rotate newly denying a subject. Resets never count, and deny entries and the subject use canonical DID comparison, including equivalent `did:peer:4` long and short forms. Export `createDeviceRevoke` and `CreateDeviceRevokeParams` to build a rotate preserving the folded snapshot and adding one denial. An already-denied subject or invalid chain throws. Both helpers require a root-chain `icp` at index zero and only `rot` events afterwards.

## 0.2.0

### Minor Changes

- Management tier on the controller log (breaking). Management authority now lives in the log: root adds Ed25519 management members (`createAdd`), which renew and remove each other and revoke edge holders without the root (`createRenew`, `createRemove`, `createRevoke`), as epoch events that merge by union rather than fork the log.

  Breaking:

  - The capability-authorised revoke is removed: `createRevokeWithKey`, `foldLogAsync`, `resolveBranchesAsync`, `createControllerIdentityAsync` / `createControllerIdentityWithKeyAsync`, `FoldOptions.verifyCapability`, `verifyRevoke` and the `unverified` / `needs-capability-verification` results are gone. `createRevoke` is now the epoch revoke builder, with new parameters.
  - `rev` leaves the root chain, which now holds only `icp` and `rot`. Every rotate is a settlement carrying a full state snapshot (`m` members, `d` denials): `createRotate` takes `snapshot` (required, build it with `snapshotOf`, which replaces `pruneDenySet`) and `seal` directly in its params — the `options` object and `CreateRotateOptions` are gone. `createReset` takes an optional snapshot.
  - **Existing logs:** every log containing a non-reset `rot` stops folding with `rotate carries no state snapshot`, not only logs carrying a chain `rev` (which now fail as an unknown critical event). Logs whose only rotates are blind resets still fold. Rebuild an affected log by re-issuing its rotates with snapshots from the seed, or recover the profile with a reset.
  - `foldLog` takes a `ControllerLog` (`{ chain, events }`) instead of an event array, and returns `head`, `applied`, `pending` and `rejected` beside `states`; `KeyState` gains `members`, `epoch` and `saturated`. `loadLog`, `createControllerIdentity` and `createControllerIdentityWithKey` take a `ControllerLog` too.
  - `LogStore` replaces `set` with an atomic `merge(did, update)`; `authoritativeStates` is replaced by `authoritativeLog`, which remembers only the chain and the current epoch's applied events.
  - `resolveBranches` takes root chains and compares them from the top generation's reset.

  - Removed exports beyond those above: the `CAPABILITY_REVOKE_NEEDS_ASYNC_FOLD`, `CAPABILITY_REVOKE_NEEDS_VERIFIER`, `CAPABILITY_VERIFIER_FAILED`, `CAPABILITY_VERIFIER_MALFORMED_ANSWER` and `REVOKE_NOT_SIGNED_BY_AUDIENCE` reasons, and the `CreateRevokeOptions`, `VerifyCapabilityParams`, `CapabilityAuthorisation` and `FoldOptions` types.

  Added:

  - Builders and checks: `createAdd`, `createRenew`, `createRemove`, `createRevoke` (epoch), `epochHeads` (the parents a new epoch event names, at most `MAX_EVENT_PARENTS`), `snapshotOf`, `isMemberEntry`, `isEpochEventShape`, `verifyEpochSignature`, `isControllerLog`.
  - Logs and memory: `authoritativeLog` with its `AuthoritativeLogParams` / `AuthoritativeLog` types, `mergeLogs`, `pruneLog`, and the `ControllerLog` type. Held epoch events are not re-verified on each resolution, and a resolution that learns nothing new hands back the stored log itself, which a `LogStore` treats as "nothing to write".
  - Resolution: the `ControllerResolver` type; `createControllerResolver` gains `resolveMember` and `frozen()`; a saturated epoch fails every resolution closed (`EPOCH_SATURATED`) until root settles, and a member that is not effective is refused with `MEMBER_NOT_EFFECTIVE`.
  - Types `AddEvent`, `RenewEvent`, `RemoveEvent`, `EpochEvent`, `EpochEventCommon`, `EpochEventType`, `EpochSigner`, `CreateAddParams`, `CreateRenewParams`, `CreateRemoveParams`, `CreateRevokeParams`, `MemberEntry`, `MemberState`, `StateSnapshot`.
  - Limits `MAX_EPOCH_EVENTS`, `MAX_LOG_EVENTS`, `MAX_EVENT_PARENTS`, `MAX_EVENT_BYTES`, `MAX_EVENT_SIGNATURES`, `MAX_FAILED_SIGNATURES`, `DEFAULT_LEASE_SECONDS`.
  - Reasons `LOG_TOO_LARGE`, `TOO_MANY_FAILED_SIGNATURES` (an input whose signatures fail past `MAX_FAILED_SIGNATURES` is refused whole), `LOG_UNFOLDABLE`, `MALFORMED_LOG`, `ROTATE_NEEDS_SNAPSHOT`, `SNAPSHOT_MALFORMED`, `SNAPSHOT_MEMBER_KEY_IS_ROOT`, `SNAPSHOT_MEMBER_DID_MISMATCH`, `SNAPSHOT_DROPS_RETIRED_KEY`.

### Patch Changes

- Updated dependencies:
  - @kokuin/token@0.6.0

## 0.1.0

### Minor Changes

- Add provideControllerIdentity: a high-level utility that resolves a did:kokuin: FullIdentity (signing + decryption) from a keystore KeyEntry and a LogStore, generating on first use and restoring afterwards. Seed-based controller identities now return FullIdentity, and a didFor helper computes the DID without signing an inception.

### Patch Changes

- Updated dependencies:
  - @kokuin/token@0.5.0
