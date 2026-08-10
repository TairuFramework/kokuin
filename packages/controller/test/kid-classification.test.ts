import {
  createIdentity,
  isIssuerKeyNotFoundError,
  isUnresolvableIssuerError,
  type SignedToken,
  stringifyToken,
  verifyToken,
} from '@kokuin/token'
import { describe, expect, test } from 'vitest'

import { createControllerResolver } from '../src/resolver.js'
import { buildTwoKeyLog, strangerKey } from './two-key-log.js'

const seed = new Uint8Array(32).fill(5)

/**
 * A token nobody signed: `iss` and `kid` are the only fields that matter, since issuer resolution
 * runs before the signature is checked. This is the shape an attacker controls end to end, and the
 * cast is what lets the test build one — `SignedToken` requires a `data` field that a real signer
 * fills in.
 */
function forgeToken(iss: string, kid?: string): string {
  return stringifyToken({
    header: { typ: 'JWT', alg: 'EdDSA', ...(kid == null ? {} : { kid }) },
    payload: { iss },
    signature: 'AAAA',
  } as unknown as SignedToken)
}

function thrownBy(promise: Promise<unknown>): Promise<unknown> {
  return promise.then(
    () => {
      throw new Error('expected the verification to reject')
    },
    (error: unknown) => error,
  )
}

describe('classification of a kid naming a key the issuer does not have', () => {
  test('matches did:peer:4 rather than reading as an unresolvable issuer', async () => {
    // did:kokuin: — a real folded log, a `kid` naming a well-formed key that is not in `k`.
    const { did, log } = buildTwoKeyLog(seed)
    const resolver = createControllerResolver({ loadLog: async () => log })
    const kokuin = await thrownBy(
      verifyToken(forgeToken(did, `#${strangerKey()}`), { methods: [resolver] }),
    )

    // did:peer:4 — the built-in method, same condition: a `kid` naming no verification method.
    const peer = await createIdentity({
      keys: [{ purpose: 'sig', alg: 'EdDSA' }],
      didMethod: 'peer:4',
    })
    const peer4 = await thrownBy(verifyToken(forgeToken(peer.longForm, '#nope')))

    // The property both must share: the issuer *was* resolved, so this is evidence about the
    // token, not a failure to check it. `@kokuin/capability`'s revocation checker denies on
    // `UnresolvableIssuerError`, and `kid` is an unauthenticated header field — if the two methods
    // disagreed here, a `did:kokuin:` issuer would have a denial switch that `did:peer:4` does not.
    expect((peer4 as Error).message).toMatch(/KidNotFound/)
    expect(isUnresolvableIssuerError(peer4)).toBe(false)
    expect((kokuin as Error).message).toMatch(/kid names a key outside the current set/)
    expect(isUnresolvableIssuerError(kokuin)).toBe(false)
    // The controller's is the branded signal, which is what carries it through
    // `resolveIssuerWithDoc` unwrapped; `did:peer:4` needs no brand since it never gets wrapped.
    expect(isIssuerKeyNotFoundError(kokuin)).toBe(true)
  })

  test('a non-fragment kid classifies the same way', async () => {
    const { did, log, controllerKey } = buildTwoKeyLog(seed)
    const resolver = createControllerResolver({ loadLog: async () => log })

    // The bare key, no `#`. Also a rejection the forger controls, so it must not be a denial
    // switch either.
    const thrown = await thrownBy(
      verifyToken(forgeToken(did, controllerKey), { methods: [resolver] }),
    )
    expect((thrown as Error).message).toMatch(/kid is not a key fragment/)
    expect(isUnresolvableIssuerError(thrown)).toBe(false)
  })

  test('the controller keeps its genuinely unresolvable failures unresolvable', async () => {
    const { did, log } = buildTwoKeyLog(seed)

    // Control for all three assertions above: the classification is per failure, not a blanket
    // "nothing from a method resolver is unresolvable". Unknown DID, a log that does not fold, and
    // a valid `kid` on an unknown DID all still deny a fail-closed caller.
    const unknown = createControllerResolver({ loadLog: async () => undefined })
    expect(
      isUnresolvableIssuerError(
        await thrownBy(verifyToken(forgeToken(did), { methods: [unknown] })),
      ),
    ).toBe(true)
    expect(
      isUnresolvableIssuerError(
        await thrownBy(verifyToken(forgeToken(did, '#z6Mkanything'), { methods: [unknown] })),
      ),
    ).toBe(true)

    // A log that does not fold to the DID asked for.
    const wrongLog = createControllerResolver({ loadLog: async () => log })
    expect(
      isUnresolvableIssuerError(
        await thrownBy(verifyToken(forgeToken('did:kokuin:zWRONG'), { methods: [wrongLog] })),
      ),
    ).toBe(true)
  })
})
