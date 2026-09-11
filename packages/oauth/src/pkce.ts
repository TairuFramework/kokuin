import { sha256 } from '@noble/hashes/sha2.js'
import { toB64U } from '@sozai/codec'
import type { Runtime } from '@sozai/runtime'

export function generateCodeVerifier(runtime: Pick<Runtime, 'getRandomValues'>): string {
  return toB64U(runtime.getRandomValues(new Uint8Array(32)))
}

export function deriveCodeChallenge(codeVerifier: string): string {
  return toB64U(sha256(new TextEncoder().encode(codeVerifier)))
}

export function generateState(runtime: Pick<Runtime, 'getRandomValues'>): string {
  return toB64U(runtime.getRandomValues(new Uint8Array(32)))
}
