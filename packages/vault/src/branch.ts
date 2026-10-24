import type { VerifiedRecordOp } from '@kokuin/records'
import { recordClaimDigest } from '@kokuin/records'

/** Compare authenticated introducing ops by claim digest, then op hash. */
export function compareVaultBranches(left: VerifiedRecordOp, right: VerifiedRecordOp): number {
  const a = recordClaimDigest(left.claim)
  const b = recordClaimDigest(right.claim)
  return a < b
    ? -1
    : a > b
      ? 1
      : left.opHash < right.opHash
        ? -1
        : left.opHash > right.opHash
          ? 1
          : 0
}
export function selectWinningBranch(branches: ReadonlyArray<VerifiedRecordOp>): VerifiedRecordOp {
  if (branches.length === 0) throw new RangeError('At least one authenticated branch is required')
  return branches.reduce((winner, candidate) =>
    compareVaultBranches(candidate, winner) > 0 ? candidate : winner,
  )
}
