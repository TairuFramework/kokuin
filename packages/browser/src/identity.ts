import { createTracer, KokuinAttributeKeys, KokuinSpanNames } from '@kokuin/otel'
import {
  CODECS,
  getDID,
  type SignedHeader,
  type SignedToken,
  type SigningIdentity,
  type SignTokenOptions,
} from '@kokuin/token'
import { p256 } from '@noble/curves/nist.js'
import { b64uFromJSON, fromUTF, toB64U } from '@sozai/codec'
import { getLogger } from '@sozai/log'
import { withSpan } from '@sozai/otel'

import { BrowserKeyStore } from './store.js'
import { getPublicKey } from './utils.js'

const tracer = createTracer('keystore.browser')
const logger = getLogger(['kokuin', 'browser'])

// P-256 curve order, used to reflect a high-S signature to its low-S form.
const P256_N = p256.Point.Fn.ORDER

// Web Crypto's subtle.sign does not enforce low-S, so ~half of ECDSA signatures
// have s > n/2 (high-S). The @kokuin/token verifier runs with `lowS: true` and
// rejects those for malleability safety, so we normalize here for cross-stack
// compatibility. `hasHighS()` is the same predicate noble's verifier applies.
function normalizeSignatureToLowS(sig: Uint8Array): Uint8Array {
  // sig is IEEE P1363 compact format: r (32 bytes) || s (32 bytes).
  const parsed = p256.Signature.fromBytes(sig, 'compact')
  if (!parsed.hasHighS()) return sig
  return new p256.Signature(parsed.r, P256_N - parsed.s).toBytes('compact')
}

async function createBrowserSigningIdentity(keyPair: CryptoKeyPair): Promise<SigningIdentity> {
  const publicKey = await getPublicKey(keyPair)
  const id = getDID(CODECS.ES256, publicKey)

  async function signToken<Payload extends Record<string, unknown> = Record<string, unknown>>(
    payload: Payload,
    options: SignTokenOptions = {},
  ): Promise<SignedToken<Payload>> {
    if (payload.iss != null && payload.iss !== id) {
      throw new Error('Invalid payload: issuer does not match signer')
    }

    const fullHeader = {
      ...(options.header ?? {}),
      typ: 'JWT',
      alg: 'ES256',
    } as SignedHeader
    const fullPayload = { ...payload, iss: id }
    const data = `${b64uFromJSON(fullHeader)}.${b64uFromJSON(fullPayload)}`

    const messageBytes = fromUTF(data)
    const signatureBuffer = await globalThis.crypto.subtle.sign(
      { name: 'ECDSA', hash: 'SHA-256' },
      keyPair.privateKey,
      messageBytes.buffer as ArrayBuffer,
    )

    // Normalize to low-S: @kokuin/token verifier rejects high-S signatures
    const normalizedSig = normalizeSignatureToLowS(new Uint8Array(signatureBuffer))

    return {
      header: fullHeader,
      payload: fullPayload,
      signature: toB64U(normalizedSig),
      data,
    }
  }

  return { id, publicKey, signToken }
}

export async function provideSigningIdentity(
  keyID: string,
  useStore?: BrowserKeyStore | Promise<BrowserKeyStore> | string,
): Promise<SigningIdentity> {
  return withSpan(
    tracer,
    KokuinSpanNames.KEYSTORE_GET_OR_CREATE,
    { attributes: { [KokuinAttributeKeys.KEYSTORE_STORE_TYPE]: 'browser' } },
    async (span) => {
      const storePromise =
        useStore == null || typeof useStore === 'string'
          ? BrowserKeyStore.open(useStore)
          : Promise.resolve(useStore)
      const store = await storePromise
      const entry = store.entry(keyID)
      const existing = await entry.getAsync()
      if (existing != null) {
        const identity = await createBrowserSigningIdentity(existing)
        span.setAttribute(KokuinAttributeKeys.AUTH_DID, identity.id)
        span.setAttribute(KokuinAttributeKeys.KEYSTORE_KEY_CREATED, false)
        return identity
      }
      const keyPair = await entry.provideAsync()
      const identity = await createBrowserSigningIdentity(keyPair)
      span.setAttribute(KokuinAttributeKeys.AUTH_DID, identity.id)
      span.setAttribute(KokuinAttributeKeys.KEYSTORE_KEY_CREATED, true)
      logger.info('New identity generated: {did}', { did: identity.id })
      return identity
    },
  )
}
