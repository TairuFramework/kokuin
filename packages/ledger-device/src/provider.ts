import { createTracer, KokuinAttributeKeys, KokuinSpanNames } from '@kokuin/otel'
import {
  CODECS,
  type FullIdentity,
  getDID,
  type IdentityProvider,
  type SignedHeader,
  type SignedToken,
  type SignTokenOptions,
} from '@kokuin/token'
import { b64uFromJSON, fromUTF, toB64U } from '@sozai/codec'
import { getLogger } from '@sozai/log'
import { withSpan } from '@sozai/otel'

import {
  CLA,
  encodeDerivationPath,
  encodeSignMessageChunks,
  INS,
  parsePublicKeyResponse,
  parseSharedSecretResponse,
  parseSignatureResponse,
} from './apdu.js'
import { LedgerDisconnectedError } from './errors.js'
import type { LedgerTransport } from './types.js'

const DEFAULT_BASE_PATH = "44'/876'"
const tracer = createTracer('ledger-identity')
const logger = getLogger(['kokuin', 'ledger-device'])

const INDEX_RE = /^\d+$/

function resolveKeyID(keyID: string, basePath: string): string {
  if (keyID.startsWith('m/')) return keyID
  if (INDEX_RE.test(keyID)) return `m/${basePath}/${keyID}'`
  throw new Error(`Invalid keyID: "${keyID}"`)
}

async function sendAPDU(
  transport: LedgerTransport,
  ins: number,
  p1: number,
  p2: number,
  data?: Uint8Array,
): Promise<Uint8Array> {
  try {
    return await transport.send(CLA, ins, p1, p2, data)
  } catch (error) {
    if (error instanceof Error && error.name === 'DisconnectedDevice') {
      // biome-ignore lint/style/useErrorCause: cause is first argument
      throw new LedgerDisconnectedError(error)
    }
    throw error
  }
}

export type LedgerIdentityProviderOptions = {
  basePath?: string
}

/**
 * An {@link IdentityProvider} backed by a Ledger device.
 *
 * Implements `IdentityProvider` and **deliberately neither `KeyStore` nor `KeyEntry`**. The
 * private key is generated on-device from the seed and never leaves it: there is nothing to
 * `getAsync`, nothing to `setAsync`, and `removeAsync` would be meaningless. Signing and ECDH
 * happen on the device, behind on-device user consent.
 *
 * This is the storage contract working as designed, not a gap in this package — a backend that
 * cannot expose key material implements the identity contract and skips the storage one. See
 * `KeyEntry` in `@kokuin/token` for the invariants the storage-backed keystores hold instead.
 *
 * Identities are cached per resolved derivation path, so repeated `provideIdentity` calls for
 * one keyID hit the device once.
 */
export function createLedgerIdentityProvider(
  transport: LedgerTransport,
  options?: LedgerIdentityProviderOptions,
): IdentityProvider<FullIdentity> {
  const basePath = options?.basePath ?? DEFAULT_BASE_PATH
  const cache = new Map<string, FullIdentity>()

  async function provideIdentity(keyID: string): Promise<FullIdentity> {
    const path = resolveKeyID(keyID, basePath)
    const cached = cache.get(path)
    if (cached != null) return cached

    return withSpan(
      tracer,
      KokuinSpanNames.KEYSTORE_GET_OR_CREATE,
      { attributes: { [KokuinAttributeKeys.KEYSTORE_STORE_TYPE]: 'ledger' } },
      async (span) => {
        const pathBytes = encodeDerivationPath(path)
        const rawKey = await sendAPDU(transport, INS.GET_PUBLIC_KEY, 0x00, 0x00, pathBytes)
        const publicKey = parsePublicKeyResponse(rawKey)
        const id = getDID(CODECS.EdDSA, publicKey)

        span.setAttribute(KokuinAttributeKeys.AUTH_DID, id)
        logger.info('Ledger identity resolved: {did}', { did: id })

        async function signToken<Payload extends Record<string, unknown> = Record<string, unknown>>(
          payload: Payload,
          options: SignTokenOptions = {},
        ): Promise<SignedToken<Payload>> {
          return withSpan(
            tracer,
            KokuinSpanNames.TOKEN_SIGN,
            {
              attributes: {
                [KokuinAttributeKeys.AUTH_DID]: id,
                [KokuinAttributeKeys.AUTH_ALGORITHM]: 'EdDSA',
              },
            },
            async () => {
              if (payload.iss != null && payload.iss !== id) {
                throw new Error('Invalid payload: issuer does not match signer')
              }

              const fullHeader = {
                ...(options.header ?? {}),
                typ: 'JWT',
                alg: 'EdDSA',
              } as SignedHeader
              const fullPayload = { ...payload, iss: id }
              const data = `${b64uFromJSON(fullHeader)}.${b64uFromJSON(fullPayload)}`

              const messageBytes = fromUTF(data)
              const chunks = encodeSignMessageChunks(pathBytes, messageBytes)

              let signatureBytes: Uint8Array = new Uint8Array(0)
              for (const chunk of chunks) {
                signatureBytes = await sendAPDU(
                  transport,
                  INS.SIGN_MESSAGE,
                  chunk.p1,
                  chunk.p2,
                  chunk.data,
                )
              }

              return {
                header: fullHeader,
                payload: fullPayload,
                signature: toB64U(parseSignatureResponse(signatureBytes)),
                data,
              }
            },
          )
        }

        async function agreeKey(ephemeralPublicKey: Uint8Array): Promise<Uint8Array> {
          const data = new Uint8Array(pathBytes.length + ephemeralPublicKey.length)
          data.set(pathBytes)
          data.set(ephemeralPublicKey, pathBytes.length)
          const response = await sendAPDU(transport, INS.ECDH_X25519, 0x00, 0x00, data)
          return parseSharedSecretResponse(response)
        }

        const identity: FullIdentity = { id, publicKey, signToken, agreeKey }
        cache.set(path, identity)
        return identity
      },
    )
  }

  return { provideIdentity }
}
