import { fromUTF, toB64U } from '@sozai/codec'
import type { Runtime } from '@sozai/runtime'

export const CLIENT_ASSERTION_TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'

const DEFAULT_TYP = 'client-authentication+jwt'
const DEFAULT_LIFETIME_SECONDS = 60

export type ClientAssertionAlgorithm = 'EdDSA' | 'ES256'

export type ClientAssertionSigner = {
  alg: ClientAssertionAlgorithm
  kid?: string
  sign(data: Uint8Array): Promise<Uint8Array>
}

export type CreateWebCryptoAssertionSignerParams = {
  alg: ClientAssertionAlgorithm
  privateKey: CryptoKey
  kid?: string
}

/**
 * Signer backed by `crypto.subtle`: Ed25519 for `EdDSA`, ECDSA P-256 with SHA-256 for `ES256`
 * (WebCrypto returns the raw r||s signature JWS expects).
 */
export function createWebCryptoAssertionSigner(
  params: CreateWebCryptoAssertionSignerParams,
): ClientAssertionSigner {
  const { alg, privateKey, kid } = params
  const algorithm = alg === 'EdDSA' ? { name: 'Ed25519' } : { name: 'ECDSA', hash: 'SHA-256' }
  return {
    alg,
    kid,
    async sign(data) {
      const signature = await globalThis.crypto.subtle.sign(
        algorithm,
        privateKey,
        data as Uint8Array<ArrayBuffer>,
      )
      return new Uint8Array(signature)
    },
  }
}

export type CreateClientAssertionParams = {
  signer: ClientAssertionSigner
  clientID: string
  audience: string
  lifetimeSeconds?: number
  /** Current time in seconds since epoch. */
  now?: () => number
  typ?: string
  getRandomValues?: Runtime['getRandomValues']
}

/** Build a signed JWT client assertion for `private_key_jwt` client authentication. */
export async function createClientAssertion(params: CreateClientAssertionParams): Promise<string> {
  const {
    signer,
    clientID,
    audience,
    lifetimeSeconds = DEFAULT_LIFETIME_SECONDS,
    now = () => Math.floor(Date.now() / 1000),
    typ = DEFAULT_TYP,
    getRandomValues = globalThis.crypto.getRandomValues.bind(globalThis.crypto),
  } = params

  const iat = now()
  const header: Record<string, string> = { alg: signer.alg, typ }
  if (signer.kid != null) {
    header.kid = signer.kid
  }
  const claims = {
    iss: clientID,
    sub: clientID,
    aud: audience,
    iat,
    exp: iat + lifetimeSeconds,
    jti: toB64U(getRandomValues(new Uint8Array(16))),
  }

  const signingInput = `${toB64U(fromUTF(JSON.stringify(header)))}.${toB64U(fromUTF(JSON.stringify(claims)))}`
  const signature = await signer.sign(fromUTF(signingInput))
  return `${signingInput}.${toB64U(signature)}`
}
