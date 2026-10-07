import {
  createRevocationChecker,
  isTokenRevokedError,
  type RevocationBackend,
  type RevocationClaims,
  type RevocationOptions,
  type VerifyTokenHook,
} from '@kokuin/capability'
import { decodeSignedToken, isIssuerKeyNotFoundError, type MethodRegistry } from '@kokuin/token'

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
 * Records come back decoded but unverified: the checker re-verifies the signature and re-compares
 * the issuer, so a row this device could not cross-check against a locally held grant is safe to
 * hand over. A record that does not decode is not evidence, so it reads as absent.
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
        return decodeSignedToken<RevocationClaims>(row.revocation_token)
      } catch {
        return undefined
      }
    },
  }
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
      <Args extends Array<unknown>, Result>(fn: (...args: Args) => Promise<Result>) =>
      async (...args: Args): Promise<Result> => {
        try {
          return await fn(...args)
        } catch (error) {
          recordFault(error)
          throw error
        }
      }
    const trackedMethods: MethodRegistry | undefined = options?.methods?.map((base) => ({
      method: base.method,
      resolve: wrap(base.resolve.bind(base)),
      ...(base.resolveHistoric == null
        ? {}
        : { resolveHistoric: wrap(base.resolveHistoric.bind(base)) }),
      ...(base.resolveDenySet == null
        ? {}
        : { resolveDenySet: wrap(base.resolveDenySet.bind(base)) }),
      ...(base.resolveAgreementKey == null
        ? {}
        : { resolveAgreementKey: wrap(base.resolveAgreementKey.bind(base)) }),
    }))
    const trackedBackend: RevocationBackend = {
      add: backend.add,
      get: wrap(backend.get),
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
