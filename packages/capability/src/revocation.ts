import type { MethodRegistry, SignedToken, SigningIdentity } from '@kokuin/token'
import { isUnresolvableIssuerError, normalizeDID, verifyToken } from '@kokuin/token'

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

/**
 * How a revocation record's issuer is resolved. A record signed by a DID whose keys are not
 * recoverable from the identifier — `did:kokuin:` — cannot be verified without the registry that
 * resolves its method, so both the backend and the checker need it.
 */
export type RevocationOptions = {
  methods?: MethodRegistry
}

export function createMemoryRevocationBackend(options?: RevocationOptions): RevocationBackend {
  const revoked = new Map<string, RevocationRecord>()
  return {
    async add(record: RevocationRecord): Promise<void> {
      // Verify the record's signature before trusting it. Without this, a forged record could
      // be stored and later used to revoke another issuer's token.
      const verified = await verifyToken<RevocationClaims>(record, { methods: options?.methods })
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

export function createRevocationChecker(
  backend: RevocationBackend,
  options?: RevocationOptions,
): VerifyTokenHook {
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
      verified = await verifyToken<RevocationClaims>(record, { methods: options?.methods })
    } catch (error) {
      // The two failures are not symmetric, and collapsing them is a fail-open.
      //
      // An *invalidly signed* record is evidence of nothing: anyone can mint one for any `jti`,
      // so ignoring it is the only safe reading — hence the `return` below, and the reason this
      // catch exists at all.
      //
      // An *unresolvable issuer* is different: a record may well be genuine and revoke this
      // token, and we simply cannot tell. "I could not check" is not evidence of non-revocation,
      // so it must propagate and fail the verification rather than pass it. For a `did:kokuin:`
      // issuer this is every record until `options.methods` carries its resolver.
      //
      // Gate that on the record's *unverified* `iss` naming this token's issuer. Reading an
      // unverified claim is sound here because of which way it decides: a record claiming some
      // *other* issuer could not revoke this token even with a perfect signature, so swallowing
      // it loses nothing; only a record claiming *this token's* issuer leaves revocation
      // genuinely unknown. Without the gate, the backend — an untrusted extension point, which
      // is why this re-verifies at all — could deny any capability by returning a record naming
      // an unresolvable DID it invented.
      if (
        isUnresolvableIssuerError(error) &&
        normalizeDID(record.payload.iss) === normalizeDID(token.payload.iss)
      ) {
        throw error
      }
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
