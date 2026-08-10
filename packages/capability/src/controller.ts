import { normalizeDID, type ResolvedSigningKey, resolveIssuer, verifyToken } from '@kokuin/token'

import {
  assertCapabilityToken,
  type CapabilityPayload,
  checkCapability,
  type DelegationChainOptions,
} from './index.js'

/**
 * A capability-authorised revoke verifier, in the shape a controller fold injects.
 *
 * Named for what it serves, not for what it imports: this file imports nothing from
 * `@kokuin/controller`, which depends on this package's siblings and would be a cycle. The fold
 * takes the callback as an option for exactly that reason, and this is the one real implementation
 * of it — kubun and kumiai must not each grow their own.
 *
 * Resolves to the signing key of the party the capability authorises, or `null` when it authorises
 * nothing here. The fold then checks the revoke's own signature against that key, which is what
 * binds the grant to its audience rather than to whoever copied it out of the public log.
 */
export type ControllerCapabilityVerifier = (
  cap: string,
  subject: string,
  target: string,
) => Promise<ResolvedSigningKey | null>

/**
 * Build the `verifyCapability` callback a `did:kokuin:` fold needs for a revoke authorised by a
 * capability rather than by the profile's own authority key.
 *
 * The returned function checks, in order:
 *
 * 1. that the serialized capability verifies as a token — its issuer is a `did:kokuin:` DID, so
 *    `options.methods` must carry a controller resolver or nothing can resolve it at all;
 * 2. that its `sub` is the controller the fold is running for. This is the binding that stops a
 *    capability minted for one profile from authorising a revoke on another: `act` and `res` say
 *    nothing about *whose* device is being denied;
 * 3. that it grants `{ act: 'revoke', res: <the target DID> }` — including through a delegation
 *    chain, and including a wildcard `res` such as the management capability's.
 *
 * All three passing yields the resolved signing key of the capability's `aud`. Handing that back
 * rather than a bare `true` is what lets the fold check the revoke event's own signature against
 * it — the audience binding, which nothing on this side of the split can do, because the event is
 * not an argument here and never should be.
 *
 * It never throws: a fold that rejected rather than returned would turn every verification failure
 * into an exception on the caller's resolve path, and the fold's own contract is that a `null`
 * means `capability does not authorise this revoke`.
 *
 * **The registry must not resolve the controller from the log being folded.** The capability is
 * issued by the very profile whose log carries the revoke, so a `loadLog` that answers with the
 * whole log would resolve the issuer by folding it, reach the same capability-authorised revoke,
 * and call this verifier again — without end. Answer with the log up to the event that carries the
 * capability, which is also the state the capability has to be checked against: a key set the log
 * rotated away afterwards must not verify a grant made under it.
 *
 * @param options forwarded to `verifyToken`, `checkCapability` and the audience resolution.
 * `methods` is effectively required — see above. `resolver` and `cache` travel with it for a
 * `did:peer:4` link in the chain, and `verifyToken` (the hook) runs on every capability including
 * the one named in the event, which is where a revocation check goes.
 */
export function createControllerCapabilityVerifier(
  options: DelegationChainOptions = {},
): ControllerCapabilityVerifier {
  return async function verifyControllerCapability(
    cap: string,
    subject: string,
    target: string,
  ): Promise<ResolvedSigningKey | null> {
    try {
      const capability = await verifyToken<CapabilityPayload>(cap, {
        atTime: options.atTime,
        cache: options.cache,
        resolver: options.resolver,
        methods: options.methods,
      })
      assertCapabilityToken(capability)
      // `checkCapability` runs the hook on every capability it verifies, but it verifies the
      // *parents* of the one handed to it — this one it takes as already established. Running it
      // here is what keeps a revocation check from having a hole exactly at the capability the
      // event names, which is the only one present when the grant is not delegated further.
      await options.verifyToken?.(capability, cap)

      if (normalizeDID(capability.payload.sub) !== normalizeDID(subject)) {
        return null
      }

      await checkCapability({ act: 'revoke', res: target }, capability.payload, options)

      // The audience may be any DID the deployment can resolve — a `did:key` device, a
      // `did:peer:4` connector, or another profile — so it goes through the same resolution the
      // capability's own issuer did, with the same three inputs.
      const [alg, publicKey] = await resolveIssuer(
        capability.payload.aud,
        {},
        options.resolver,
        options.methods,
      )
      return { alg, publicKey }
    } catch {
      // Every failure is the same answer here, including the two `@kokuin/token` keeps apart:
      // `UnresolvableIssuerError` (nothing was learned about the capability) and
      // `IssuerKeyNotFoundError` (the issuer resolved and the capability is bad). The distinction
      // exists because a caller that treats "could not check" as "checked and fine" fails open —
      // and this caller does the opposite with both. A `null` makes the fold reject the whole
      // log, so an unverifiable capability leaves the controller unresolvable rather than
      // silently applying a revoke nobody could check.
      return null
    }
  }
}
