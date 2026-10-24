import { fromB64U, toB64U } from '@sozai/codec'

export function isCanonicalCompactToken(token: string): boolean {
  const segments = token.split('.')

  if (segments.length !== 3) return false

  try {
    return segments.every((segment) => toB64U(fromB64U(segment)) === segment)
  } catch {
    return false
  }
}
