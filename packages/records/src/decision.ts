import type { CryptoOptions, MethodRegistry } from '@kokuin/token'

import { compareRecordDecisionHLC, parseCanonicalHLC } from './clock.js'
import { type VerifiedRecordOp, verifySignedRecord } from './op.js'
import { RecordClaimError, type RecordKey, type SignedRecord } from './record.js'

export type RecordDecisionDigestParams = {
  record: SignedRecord
  opKind: string
  methods?: MethodRegistry
  options?: CryptoOptions
}

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
    const contentDigest = op.contentDigest
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
      .filter(({ op }) => {
        return (
          decisionStamp(op, stampSource) === winner.decisionHLC &&
          op.contentDigest === winner.contentDigest
        )
      })
      .map(({ copy }) => copy)
      .sort((a, b) => (a.opHash < b.opHash ? -1 : a.opHash > b.opHash ? 1 : 0)),
  }
}

/** Stable identity of signed content, independent of the identity that signed this copy. */
export async function recordDecisionDigest({
  record,
  opKind,
  methods,
  options,
}: RecordDecisionDigestParams): Promise<string> {
  const op = await verifySignedRecord({
    record: record,
    opKind: opKind,
    methods: methods,
    options: options,
  })
  if (op === null) throw new RecordClaimError({ message: 'Record signature is invalid' })
  return op.contentDigest
}
