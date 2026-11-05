import type { VerifiedRecordOp } from '@kokuin/records'

/** Compare authenticated introducing ops by claim digest, then op hash. */
export type CompareVaultBranchesParams = { left: VerifiedRecordOp; right: VerifiedRecordOp }

export function compareVaultBranches({ right, left }: CompareVaultBranchesParams): number {
  const a = left.contentDigest
  const b = right.contentDigest

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

  return branches.reduce((winner, candidate) => {
    return compareVaultBranches({ left: candidate, right: winner }) > 0 ? candidate : winner
  })
}
