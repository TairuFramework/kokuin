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

// Spread into both `verifyToken` calls, so the two paths cannot drift apart. Typed as a `Pick` of
// `VerifyTokenOptions` rather than re-spelled inline: it keeps the three names tied to the source
// of truth, and makes the set this forwards legible next to the set `verifyToken` accepts. It does
// not force a future field on `VerifyTokenOptions` to be considered here — nothing in the type
// system can — but it puts the two lists side by side for whoever adds one.
//
// `historic` is set rather than forwarded: a revocation record is an artefact its issuer minted at
// some point in the past, and the whole point of holding one is that it stays checkable afterwards.
// Without it, an issuer whose key set rotates — `did:kokuin:` — would have every record it ever
// signed stop verifying at its next routine rotate, which on this path reads as "not revoked". See
// `DIDMethodResolver.resolveHistoric` for what accepting a superseded key does and does not
// establish, and note that a `reset` still invalidates the record: it discards the generation.
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
 * Does this record name a key its issuer published and has since **denied**?
 *
 * The distinction this draws is what keeps the remedy for a leaked key from undoing the profile's
 * own revocations. Revoking a key makes every record that key signed stop verifying, and the catch
 * below reads a verification failure as "not evidence of anything" — so denying a compromised key
 * silently resurrected every capability its records had revoked, on the one path that must never
 * fail open.
 *
 * A record naming a key the log never published is still a forgery, and still ignored: anyone can
 * mint one for any `jti`, which is exactly the plant-a-record denial of service the catch exists to
 * stop. A record naming a **denied** key is not that. Producing it required the private half of a
 * key the DID itself published, so the only party who could have written it is the issuer or
 * whoever compromised it — and honouring it can only ever subtract authority, never grant any.
 * Between "the owner's revocations lapse the moment they act on a compromise" and "the thief's
 * planted revocations survive that remedy", the second is the bounded harm.
 *
 * Only reachable for a `did:kokuin:` issuer, whose resolver publishes a deny set. A method with no
 * deny set answers `false` and nothing changes for it. The `kid` and the deny set's key entries are
 * the same spelling — `#<the multibase key as it appears in `k`>` — so this is a membership test,
 * never an enumeration: the set is heterogeneous and also holds revoked DIDs.
 *
 * A resolver that has a deny set and cannot produce it throws, which fails closed — the same
 * direction `assertAudienceNotRevoked` takes for the same reason.
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
      const sameIssuer = normalizeDID(record.payload.iss) === normalizeDID(token.payload.iss)
      if (isUnresolvableIssuerError(error) && sameIssuer) {
        throw error
      }
      // A third reading, between the two above: the record is signed by a key this issuer once
      // published and has since revoked. Not "evidence of nothing" — see {@link namesADeniedKey}.
      // Checked after the two cheap classifications and only for this token's own issuer, since a
      // record naming anyone else could not revoke this token however it was signed.
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
