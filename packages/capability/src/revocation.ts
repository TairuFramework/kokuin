import type { SignedToken, SigningIdentity } from '@kokuin/token'
import { normalizeDID, verifyToken } from '@kokuin/token'

import type { CapabilityToken, VerifyTokenHook } from './index.js'
import { now } from './index.js'

export type RevocationClaims = {
  jti: string
  iss: string
  rev: true
  iat: number
}

/**
 * A revocation record is an authenticated statement, signed by a token's issuer, that the
 * token identified by `jti` is revoked. The signature and the `iss` claim let a checker verify
 * that only the issuer of a token can revoke it — an unauthenticated record cannot revoke
 * another issuer's token.
 */
export type RevocationRecord = SignedToken<RevocationClaims>

export type RevocationBackend = {
  /**
   * Store a revocation record. Implementations SHOULD reject records that fail signature
   * verification, but the checker re-verifies on use and does not rely on this.
   */
  add(record: RevocationRecord): Promise<void>
  get(jti: string): Promise<RevocationRecord | undefined>
}

export function createMemoryRevocationBackend(): RevocationBackend {
  const revoked = new Map<string, RevocationRecord>()
  return {
    async add(record: RevocationRecord): Promise<void> {
      // Verify the record's signature before trusting it. Without this, a forged record could
      // be stored and later used to revoke another issuer's token.
      const verified = await verifyToken<RevocationClaims>(record)
      if (verified.payload.rev !== true || typeof verified.payload.jti !== 'string') {
        throw new Error('Invalid revocation record')
      }
      revoked.set(verified.payload.jti, record)
    },
    async get(jti: string): Promise<RevocationRecord | undefined> {
      return revoked.get(jti)
    },
  }
}

export function createRevocationChecker(backend: RevocationBackend): VerifyTokenHook {
  return async (token: CapabilityToken, _raw: string): Promise<void> => {
    const jti = token.payload.jti
    if (jti == null) {
      return
    }
    const record = await backend.get(jti)
    if (record == null) {
      return
    }
    // Re-verify at the point of use: the backend is an extension point and may return an
    // unverified record. A record with an invalid signature does not revoke anything.
    let verified: RevocationRecord
    try {
      verified = await verifyToken<RevocationClaims>(record)
    } catch {
      return
    }
    // Only the issuer of a token may revoke it: the record's issuer must match the token's.
    // A revocation signed by anyone else does not apply.
    if (normalizeDID(verified.payload.iss) === normalizeDID(token.payload.iss)) {
      throw new Error(`Token revoked: ${jti}`)
    }
  }
}

export async function createRevocationRecord(
  signer: SigningIdentity,
  jti: string,
): Promise<RevocationRecord> {
  // `signToken` injects the signer's own DID as `iss`, so a caller cannot mint a record for
  // another issuer. The record names no audience, so a `did:peer:4` signer embeds its long form
  // there — the checker above normalizes both sides before comparing, so either form matches.
  return (await signer.signToken({ jti, rev: true, iat: now() })) as RevocationRecord
}
