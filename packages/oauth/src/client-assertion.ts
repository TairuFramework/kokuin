import { fromUTF, toB64U } from '@sozai/codec'
import type { Runtime } from '@sozai/runtime'

export const CLIENT_ASSERTION_TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'

const DEFAULT_TYP = 'client-authentication+jwt'
const DEFAULT_LIFETIME_SECONDS = 60

export type ClientAssertionAlgorithm = 'EdDSA' | 'ES256'

function assertSupportedAlgorithm(alg: string): asserts alg is ClientAssertionAlgorithm {
  if (alg !== 'EdDSA' && alg !== 'ES256') {
    throw new Error(`Unsupported client assertion algorithm: ${alg}`)
  }
}

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
  assertSupportedAlgorithm(alg)
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
  /** Seconds from `iat` to `exp`: a positive integer, default `60`. */
  lifetimeSeconds?: number
  /** Current time in seconds since epoch. */
  now?: () => number
  typ?: string
  /** Source of randomness for the `jti` claim, defaults to `globalThis.crypto`. */
  runtime?: Pick<Runtime, 'getRandomValues'>
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
    runtime,
  } = params

  assertSupportedAlgorithm(signer.alg)
  // Anything else gives an assertion that is already expired or has a malformed `exp`.
  if (!Number.isInteger(lifetimeSeconds) || lifetimeSeconds <= 0) {
    throw new Error(
      `Client assertion lifetimeSeconds must be a positive integer, got: ${lifetimeSeconds}`,
    )
  }
  const randomBytes = (length: number) =>
    runtime == null
      ? globalThis.crypto.getRandomValues(new Uint8Array(length))
      : runtime.getRandomValues(new Uint8Array(length))
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
    jti: toB64U(randomBytes(16)),
  }

  const signingInput = `${toB64U(fromUTF(JSON.stringify(header)))}.${toB64U(fromUTF(JSON.stringify(claims)))}`
  const signature = await signer.sign(fromUTF(signingInput))
  return `${signingInput}.${toB64U(signature)}`
}
