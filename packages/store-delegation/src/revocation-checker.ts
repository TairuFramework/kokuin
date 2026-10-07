import {
  createRevocationChecker,
  isTokenRevokedError,
  type RevocationBackend,
  type RevocationClaims,
  type RevocationOptions,
  type VerifyTokenHook,
} from '@kokuin/capability'
import {
  decodeSignedToken,
  isIssuerKeyNotFoundError,
  type MethodRegistry,
  normalizeDID,
} from '@kokuin/token'

import type { DelegationStoreAPI } from './api.js'

const VERIFIED_REVOCATION_BRAND = '@kokuin/store-delegation/VerifiedRevocationError'

/** A revocation proved by `@kokuin/capability` after the store and resolvers answered cleanly. */
export class VerifiedRevocationError extends Error {
  get brand(): string {
    return VERIFIED_REVOCATION_BRAND
  }

  constructor(message: string, options?: ErrorOptions) {
    super(message, options)
    this.name = 'VerifiedRevocationError'
  }
}

/**
 * Revocation backend over the delegation store.
 *
 * The store holds one row per (capability, revoker): a `jti` alone names several claims, of which
 * only the one signed by the capability's own issuer binds. `get` is scoped to that issuer so a
 * co-member's claim about the same `jti` can neither answer in its place nor hide it.
 *
 * Records come back decoded but unverified. The checker re-verifies the signature and revokes only
 * when the record is signed by the capability's own issuer and its payload states `rev: true` for
 * the capability's `jti`. So a row this device could not cross-check against a locally held grant
 * can revoke at most the one capability its signed content names, and only if that capability's
 * issuer signed it; the row's own `jti` and `revoker_did` columns grant nothing. A record that does
 * not decode to an object header and payload, or whose payload names a different `jti` than the one
 * asked for, is not evidence, so it reads as absent.
 */
export function createDelegationRevocationBackend(api: DelegationStoreAPI): RevocationBackend {
  return {
    async add(): Promise<void> {
      // No-op. Revocations enter the delegation store through explicit local mint and
      // broadcast/invite arrival paths, both of which carry context this adapter does not have
      // (hlc, capability cross-check). The checker only consumes `get`, so this stub satisfies the
      // interface without offering a second, lossy write path.
    },
    async get(jti, issuer) {
      // Store errors propagate: a lookup that failed is not "no record".
      const row = await api.getRevocationByIssuer(jti, issuer)
      if (row == null) {
        return undefined
      }
      try {
        const record = decodeSignedToken<RevocationClaims>(row.revocation_token)
        // A shape check, not verification: the checker reads `header` and `payload` fields, and
        // re-checks the `jti` binding itself. A record about another `jti` is misfiled.
        return isPlainObject(record.header) &&
          isPlainObject(record.payload) &&
          record.payload.jti === jti
          ? record
          : undefined
      } catch {
        return undefined
      }
    },
  }
}

function isPlainObject(value: unknown): boolean {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

type Verdict = (token: Parameters<VerifyTokenHook>[0], raw: string) => Promise<boolean>

function createDelegationRevocationVerdict(
  api: DelegationStoreAPI,
  options?: RevocationOptions,
): Verdict {
  const backend = createDelegationRevocationBackend(api)
  return async (token, raw) => {
    // Capability's checker reads an unresolvable or failing dependency in several ways, some of
    // which end in a normal return. Recording the first fault at its source keeps a resolver or
    // store that could not answer from ever reading as "not revoked".
    //
    // Resolver faults count only for this token's own issuer. A record naming another issuer
    // cannot revoke this capability, so a fault resolving it hides nothing, and recording it would
    // let a planted record deny the check. Every resolver method takes the subject DID first.
    const ownIssuer = normalizeDID(token.payload.iss)
    const isOwnIssuer = (args: Array<unknown>): boolean => {
      const did = args[0]
      return typeof did === 'string' && normalizeDID(did.split('#')[0] ?? did) === ownIssuer
    }
    let dependencyFault: unknown
    let hadDependencyFault = false
    const recordFault = (error: unknown): void => {
      // Not a fault: "this issuer has no such key" is an answer. Capability's checker reads it as
      // a forgery (ignored) or a denied key (revoked); recording it would turn the first into a
      // plant-a-record denial and the second into a rejection instead of a revocation.
      if (isIssuerKeyNotFoundError(error)) {
        return
      }
      if (!hadDependencyFault) {
        dependencyFault = error
        hadDependencyFault = true
      }
    }
    const wrap =
      <Args extends Array<unknown>, Result>(
        fn: (...args: Args) => Promise<Result>,
        counts: (args: Args) => boolean,
      ) =>
      async (...args: Args): Promise<Result> => {
        try {
          return await fn(...args)
        } catch (error) {
          if (counts(args)) {
            recordFault(error)
          }
          throw error
        }
      }
    const trackedMethods: MethodRegistry | undefined = options?.methods?.map((base) => ({
      method: base.method,
      resolve: wrap(base.resolve.bind(base), isOwnIssuer),
      ...(base.resolveHistoric == null
        ? {}
        : { resolveHistoric: wrap(base.resolveHistoric.bind(base), isOwnIssuer) }),
      ...(base.resolveDenySet == null
        ? {}
        : { resolveDenySet: wrap(base.resolveDenySet.bind(base), isOwnIssuer) }),
      ...(base.resolveAgreementKey == null
        ? {}
        : { resolveAgreementKey: wrap(base.resolveAgreementKey.bind(base), isOwnIssuer) }),
    }))
    const trackedBackend: RevocationBackend = {
      add: backend.add,
      // Store faults always count: a failed read may be hiding this issuer's own record.
      get: wrap(backend.get, () => true),
    }
    try {
      await createRevocationChecker(trackedBackend, { ...options, methods: trackedMethods })(
        token,
        raw,
      )
    } catch (error) {
      if (hadDependencyFault) throw dependencyFault
      if (isTokenRevokedError(error)) return true
      throw error
    }
    // Also on a normal return: the checker ignores some failures (a record naming another
    // issuer), and a fault there must still not read as "not revoked".
    if (hadDependencyFault) throw dependencyFault
    return false
  }
}

/** Adapt the revocation verdict to the throwing `VerifyTokenHook` contract. */
export function createDelegationRevocationChecker(
  api: DelegationStoreAPI,
  options?: RevocationOptions,
): VerifyTokenHook & { verdict: Verdict } {
  const verdict = createDelegationRevocationVerdict(api, options)
  const checker: VerifyTokenHook = async (token, raw) => {
    if (await verdict(token, raw)) {
      throw new VerifiedRevocationError(`Token revoked: ${token.payload.jti}`)
    }
  }
  return Object.assign(checker, { verdict })
}
