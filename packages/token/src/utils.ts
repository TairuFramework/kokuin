import { b64uFromJSON, b64uToJSON } from '@sozai/codec'

import type { SignedToken, Token } from './types.js'

export function concatBytes(...parts: Array<Uint8Array>): Uint8Array {
  const out = new Uint8Array(parts.reduce((total, part) => total + part.length, 0))
  let offset = 0
  for (const part of parts) {
    out.set(part, offset)
    offset += part.length
  }
  return out
}

/**
 * Convert a Token object to its JWT string representation.
 */
export function stringifyToken(token: Token): string {
  const parts = [b64uFromJSON(token.header), b64uFromJSON(token.payload)]
  if (token.signature != null) {
    parts.push(token.signature)
  }
  return parts.join('.')
}

/**
 * Parse a signed token string without verifying it. `data` keeps the original signed segments.
 */
export function decodeSignedToken<
  Payload extends Record<string, unknown> = Record<string, unknown>,
>(token: string): SignedToken<Payload> {
  const [header, payload, signature, ...rest] = token.split('.')
  if (!header || !payload || !signature || rest.length > 0) {
    throw new Error('Invalid token format: expected 3 parts separated by dots')
  }
  return {
    data: `${header}.${payload}`,
    header: b64uToJSON(header),
    payload: b64uToJSON(payload),
    signature,
  } as SignedToken<Payload>
}
