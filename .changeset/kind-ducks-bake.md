---
"@kokuin/controller": minor
---

Management tier on the controller log (breaking). Management authority now lives in the log: root adds Ed25519 management members (`createAdd`), which renew and remove each other and revoke edge holders without the root (`createRenew`, `createRemove`, `createRevoke`), as epoch events that merge by union rather than fork the log.

Breaking:

- The capability-authorised revoke is removed: `createRevokeWithKey`, `foldLogAsync`, `resolveBranchesAsync`, `createControllerIdentityAsync` / `createControllerIdentityWithKeyAsync`, `FoldOptions.verifyCapability`, `verifyRevoke` and the `unverified` / `needs-capability-verification` results are gone. `createRevoke` is now the epoch revoke builder, with new parameters.
- `rev` leaves the root chain, which now holds only `icp` and `rot`. Every rotate is a settlement carrying a full state snapshot (`m` members, `d` denials): `createRotate` requires `options.snapshot` (build it with `snapshotOf`, which replaces `pruneDenySet`), and `createReset` takes an optional one.
- **Existing logs:** every log containing a non-reset `rot` stops folding with `rotate carries no state snapshot`, not only logs carrying a chain `rev` (which now fail as an unknown critical event). Logs whose only rotates are blind resets still fold. Rebuild an affected log by re-issuing its rotates with snapshots from the seed, or recover the profile with a reset.
- `foldLog` takes a `ControllerLog` (`{ chain, events }`) instead of an event array, and returns `head`, `applied`, `pending` and `rejected` beside `states`; `KeyState` gains `members`, `epoch` and `saturated`. `loadLog`, `createControllerIdentity` and `createControllerIdentityWithKey` take a `ControllerLog` too.
- `LogStore` replaces `set` with an atomic `merge(did, update)`; `authoritativeStates` is replaced by `authoritativeLog`, which remembers only the chain and the current epoch's applied events.
- `resolveBranches` takes root chains and compares them from the top generation's reset.

Added: `createControllerResolver` gains `resolveMember` and `frozen()`; `mergeLogs`, `pruneLog`, `isControllerLog`, `isEpochEventShape`, `verifyEpochSignature`; limits `MAX_EPOCH_EVENTS`, `MAX_LOG_EVENTS`, `MAX_EVENT_PARENTS`, `MAX_EVENT_BYTES`, `MAX_EVENT_SIGNATURES`, `DEFAULT_LEASE_SECONDS`; a saturated epoch fails every resolution closed (`EPOCH_SATURATED`) until root settles.
