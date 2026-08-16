import type { DIDCache, DIDResolver, MethodRegistry, SignedToken } from '@kokuin/token'

/** Hook called for each token during verification. Throw to reject. */
export type VerifyTokenHook = (token: CapabilityToken, raw: string) => void | Promise<void>

/** Options for delegation chain validation */
export type DelegationChainOptions = {
  /** Time to use for expiration checks (seconds since epoch). Defaults to now(). */
  atTime?: number
  /** Maximum depth of delegation chain. Defaults to {@link DEFAULT_MAX_DELEGATION_DEPTH}. */
  maxDepth?: number
  /** Optional hook called for each token in the chain after verification. Can be used for revocation checks. */
  verifyToken?: VerifyTokenHook
  /** Optional DID cache for resolving did:peer:4 issuers. Populated on long-form first contact. */
  cache?: DIDCache
  /** Optional resolver for did:peer:4 short forms not in cache. */
  resolver?: DIDResolver
  /**
   * Optional DID method registry, forwarded to `verifyToken` for every capability in the chain.
   * Required when any link is issued by a method that cannot be resolved from the identifier
   * alone, such as `did:kokuin:`.
   */
  methods?: MethodRegistry
}

/** Options for capability creation */
export type CreateCapabilityOptions = {
  /**
   * Parent capability token (stringified) that authorizes this delegation.
   * Required when creating a capability where signer is not the subject.
   * The signer must be the audience of the parent capability.
   */
  parentCapability?: string
  /** Optional DID cache for resolving did:peer:4 issuers. Populated on long-form first contact. */
  cache?: DIDCache
  /** Optional resolver for did:peer:4 short forms not in cache. */
  resolver?: DIDResolver
  /**
   * Optional DID method registry, forwarded to `verifyToken` when verifying the parent
   * capability. Required when the parent is issued by a method that cannot be resolved from the
   * identifier alone, such as `did:kokuin:` — the same reason `DelegationChainOptions` carries
   * it for every other link in a chain. A parent issued by a `did:peer:4` short form has the
   * identical resolution problem, so `cache` and `resolver` travel with it here too, rather than
   * leaving this one call site one option short of its neighbours.
   */
  methods?: MethodRegistry
}

export type Permission = {
  act: string | Array<string>
  res: string | Array<string>
}

export type CapabilityPayload = Permission & {
  iss: string
  sub: string
  aud: string
  exp?: number
  iat?: number
  jti?: string
  /**
   * Proof-of-possession key the audience must hold, pinned at mint time — see
   * {@link ConfirmationClaim}. Optional in general (a holder proving itself by signing a token needs
   * nothing here), but **required** by `createControllerCapabilityVerifier`, where the holder signs a
   * raw key event naming nobody and resolving the audience instead would let its key rotation brick
   * the profile.
   */
  cnf?: ConfirmationClaim
}

/**
 * RFC 7800's `cnf` (confirmation) claim: the key the presenter must prove possession of. The
 * registered claim for the job, so the wire format is standard rather than a house invention.
 *
 * The member is `kid`, not `jwk`: here the identifier **is** the key (multicodec-tagged multibase,
 * self-describing, no lookup) — the same `kid` convention `did:kokuin:` fixed for headers and the
 * encoding a controller log uses for `k`. `cnf.jwk` would add a second encoding, JWK serialisation,
 * and canonical comparison, buying nothing the tagged form does not.
 *
 * Only `kid` is understood; any other member (a legitimate `jwk`, `jwe`, `jku`) fails closed rather
 * than resolving, because resolving is the bug this claim removes. The type stays open so carrying
 * one is a typing question, not a cast — the extensibility has to be real in the type, not only wire.
 */
export type ConfirmationClaim = { kid?: string; [member: string]: unknown }

export type CapabilityToken<
  Payload extends CapabilityPayload = CapabilityPayload,
  Header extends Record<string, unknown> = Record<string, unknown>,
> = SignedToken<Payload, Header>

export type SignCapabilityPayload = Omit<CapabilityPayload, 'iss'> & { iss?: string }
