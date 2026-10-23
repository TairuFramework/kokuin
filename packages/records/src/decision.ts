import { compareRecordDecisionHLC, parseCanonicalHLC } from './clock.js'
import { type VerifiedRecordOp, verifySignedRecord } from './op.js'
import { RecordClaimError, type RecordKey, recordClaimDigest, type SignedRecord } from './record.js'

export type RecordDecision = {
  key: RecordKey
  decisionHLC: string
  contentDigest: string
  copies: ReadonlyArray<SignedRecord>
}

export type VerifiedRecordCopy = { copy: SignedRecord; op: VerifiedRecordOp }

function decisionStamp(op: VerifiedRecordOp, source: 'hlc' | 'version'): string | null {
  if (source === 'hlc') return op.claim.hlc
  return typeof op.claim.meta.version === 'string' ? op.claim.meta.version : null
}

/** Select one signed content decision while retaining every verified copy of it. */
export function recordDecisionFromVerifiedCopies(
  key: RecordKey,
  entries: ReadonlyArray<VerifiedRecordCopy>,
  stampSource: 'hlc' | 'version',
): RecordDecision | null {
  let winner: { decisionHLC: string; contentDigest: string } | null = null
  for (const { op } of entries) {
    const decisionHLC = decisionStamp(op, stampSource)
    if (decisionHLC === null || parseCanonicalHLC(decisionHLC) === null) continue
    const contentDigest = recordClaimDigest(op.claim)
    if (
      winner === null ||
      compareRecordDecisionHLC(decisionHLC, winner.decisionHLC) > 0 ||
      (decisionHLC === winner.decisionHLC && contentDigest > winner.contentDigest)
    ) {
      winner = { decisionHLC, contentDigest }
    }
  }
  if (winner === null) return null
  return {
    key,
    ...winner,
    copies: entries
      .filter(
        ({ op }) =>
          decisionStamp(op, stampSource) === winner.decisionHLC &&
          recordClaimDigest(op.claim) === winner.contentDigest,
      )
      .map(({ copy }) => copy)
      .sort((a, b) => (a.opHash < b.opHash ? -1 : a.opHash > b.opHash ? 1 : 0)),
  }
}

/** Stable identity of signed content, independent of the identity that signed this copy. */
export async function recordDecisionDigest(record: SignedRecord): Promise<string> {
  const op = await verifySignedRecord(record)
  if (op === null) throw new RecordClaimError('Record signature is invalid')
  return recordClaimDigest(op.claim)
}
