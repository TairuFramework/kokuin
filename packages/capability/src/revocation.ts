import type {
  DIDCache,
  DIDResolver,
  MethodRegistry,
  SignedToken,
  SigningIdentity,
  VerifyTokenOptions,
} from '@kokuin/token'
import {
  findMethodResolver,
  isIssuerKeyNotFoundError,
  isUnresolvableIssuerError,
  normalizeDID,
  verifyToken,
} from '@kokuin/token'

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
 * How a revocation record's issuer is resolved, mirroring the three resolution inputs
 * `DelegationChainOptions` already carries.
 *
 * All three matter now that an unresolvable issuer is a hard rejection rather than a silent pass:
 * a record this cannot resolve denies the capability, so every issuer shape a deployment uses
 * must have a way in. Both the backend and the checker take these, since each verifies
 * independently.
 */
export type RevocationOptions = {
  /**
   * DID method registry. Required when a record is signed by a method that cannot be resolved
   * from the identifier alone, such as `did:kokuin:`.
   */
  methods?: MethodRegistry
  /** Resolver for `did:peer:4` short forms not in `cache`. */
  resolver?: DIDResolver
  /** DID cache for `did:peer:4` issuers. Populated on long-form first contact. */
  cache?: DIDCache
}

// Spread into both `verifyToken` calls so the two paths cannot drift. `historic` is set, not
// forwarded: a revocation record is a past-minted artefact that must stay checkable, so without it a
// rotating issuer (`did:kokuin:`) would have every record it signed stop verifying at its next
// routine rotate — reading here as "not revoked". A `reset` still invalidates it (it discards the
// generation). See `DIDMethodResolver.resolveHistoric`.
function verifyOptions(
  options?: RevocationOptions,
): Pick<VerifyTokenOptions, 'methods' | 'resolver' | 'cache' | 'historic'> {
  return {
    methods: options?.methods,
    resolver: options?.resolver,
    cache: options?.cache,
    historic: true,
  }
}

export function createMemoryRevocationBackend(options?: RevocationOptions): RevocationBackend {
  const revoked = new Map<string, RevocationRecord>()
  return {
    async add(record: RevocationRecord): Promise<void> {
      // Verify the record's signature before trusting it. Without this, a forged record could
      // be stored and later used to revoke another issuer's token.
      const verified = await verifyToken<RevocationClaims>(record, verifyOptions(options))
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

/**
 * Does this record name a key its issuer published and has since **denied**? The distinction keeps
 * the remedy for a leaked key from undoing the profile's own revocations: revoking a key makes every
 * record it signed stop verifying, and the catch below reads that as "not evidence of anything" — so
 * without this, denying a compromised key silently resurrects every capability its records revoked.
 *
 * A record naming a never-published key is still a forgery, ignored (anyone can mint one — the
 * plant-a-record DoS the catch stops). A **denied** key is different: producing the record needed the
 * private half of a key the DID published, so only the issuer or whoever compromised it could, and
 * honouring it only ever subtracts authority. The thief's planted revocations surviving the remedy is
 * the bounded harm.
 *
 * Only reachable for a `did:kokuin:` issuer, whose resolver publishes a deny set; other methods answer
 * `false`. `kid` and the deny set's key entries share one spelling, so this is a membership test. A
 * resolver that has a deny set and cannot produce it throws — fails closed, like
 * `assertAudienceNotRevoked`.
 */
async function namesADeniedKey(
  record: RevocationRecord,
  options?: RevocationOptions,
): Promise<boolean> {
  const kid = record.header?.kid
  const iss = record.payload?.iss
  if (typeof kid !== 'string' || typeof iss !== 'string' || options?.methods == null) {
    return false
  }
  const resolveDenySet = findMethodResolver(options.methods, iss)?.resolveDenySet
  if (resolveDenySet == null) {
    return false
  }
  return (await resolveDenySet(iss)).has(kid)
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
      verified = await verifyToken<RevocationClaims>(record, verifyOptions(options))
    } catch (error) {
      // The two failures are not symmetric; collapsing them fails open. An *invalidly signed* record
      // is evidence of nothing (anyone can mint one), so it is ignored — the `return` below. An
      // *unresolvable issuer* is different: the record may be genuine and we cannot tell, so "could
      // not check" must propagate rather than pass.
      //
      // Gated on the record's *unverified* `iss` naming this token's issuer, which is sound because of
      // which way it decides: a record claiming another issuer could not revoke this token anyway.
      // Without the gate, the untrusted backend could deny any capability by returning a record naming
      // an unresolvable DID it invented.
      const sameIssuer = normalizeDID(record.payload.iss) === normalizeDID(token.payload.iss)
      if (isUnresolvableIssuerError(error) && sameIssuer) {
        throw error
      }
      // A third reading: signed by a key this issuer published and has since revoked — not "evidence
      // of nothing", see {@link namesADeniedKey}. Only for this token's own issuer.
      if (
        isIssuerKeyNotFoundError(error) &&
        sameIssuer &&
        (await namesADeniedKey(record, options))
      ) {
        // Same message as the verified path below, so a caller matching on it does not have to
        // learn a second spelling; the resolution failure rides along as `cause` for a reader.
        throw new Error(`Token revoked: ${jti}`, { cause: error })
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
