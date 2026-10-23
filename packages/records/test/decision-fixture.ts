import { blake3 } from '@noble/hashes/blake3.js'
import { canonicalStringify, fromB64U, fromUTF, toB64U, toUTF } from '@sozai/codec'

import type { RecordClaim, RecordDecision, SignedRecord } from '../src/index.js'

export function decisionOf(record: SignedRecord): RecordDecision {
  const token = JSON.parse(toUTF(fromB64U(record.opJWT.split('.')[1] as string))) as {
    claim: string
  }
  const claim = JSON.parse(toUTF(fromB64U(token.claim))) as RecordClaim
  return {
    key: { type: record.type, owner: record.owner, id: record.id },
    decisionHLC: typeof claim.meta.version === 'string' ? claim.meta.version : claim.hlc,
    contentDigest: toB64U(
      blake3(
        typeof claim.meta.version === 'string'
          ? fromUTF(canonicalStringify({ ...claim, hlc: claim.meta.version }))
          : fromB64U(token.claim),
        { dkLen: 32 },
      ),
    ),
    copies: [record],
  }
}
