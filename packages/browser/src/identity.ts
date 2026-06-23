import {
  CODECS,
  getDID,
  type SignedHeader,
  type SignedToken,
  type SigningIdentity,
  type SignTokenOptions,
} from '@kokuin/token'
import { b64uFromJSON, fromUTF, toB64U } from '@sozai/codec'
import { getLogger } from '@sozai/log'
import { AttributeKeys, createTracer, SpanNames, withSpan } from '@sozai/otel'

import { BrowserKeyStore } from './store.js'
import { getPublicKey } from './utils.js'

const tracer = createTracer('keystore.browser')
const logger = getLogger(['kokuin', 'browser'])

// P-256 curve order n and half-order for low-S normalization.
// Web Crypto API produces raw r||s signatures that may have s > n/2 (high-S).
// The @kokuin/token verifier rejects high-S signatures for malleability safety,
// so we normalize here to ensure cross-stack compatibility.
const P256_N = BigInt('0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551')
const P256_HALF_N = P256_N >> 1n

function normalizeSignatureToLowS(sig: Uint8Array): Uint8Array {
  // sig is IEEE P1363 compact format: r (32 bytes) || s (32 bytes)
  let s = 0n
  for (let i = 32; i < 64; i++) {
    s = (s << 8n) | BigInt(sig[i])
  }
  if (s <= P256_HALF_N) return sig
  // Compute n - s and re-encode
  const ns = P256_N - s
  const out = new Uint8Array(64)
  out.set(sig.slice(0, 32))
  let tmp = ns
  for (let i = 63; i >= 32; i--) {
    out[i] = Number(tmp & 0xffn)
    tmp >>= 8n
  }
  return out
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
    SpanNames.KEYSTORE_GET_OR_CREATE,
    { attributes: { [AttributeKeys.KEYSTORE_STORE_TYPE]: 'browser' } },
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
        span.setAttribute(AttributeKeys.AUTH_DID, identity.id)
        span.setAttribute(AttributeKeys.KEYSTORE_KEY_CREATED, false)
        return identity
      }
      const keyPair = await entry.provideAsync()
      const identity = await createBrowserSigningIdentity(keyPair)
      span.setAttribute(AttributeKeys.AUTH_DID, identity.id)
      span.setAttribute(AttributeKeys.KEYSTORE_KEY_CREATED, true)
      logger.info('New identity generated: {did}', { did: identity.id })
      return identity
    },
  )
}
