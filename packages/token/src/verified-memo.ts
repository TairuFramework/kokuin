import type { SignatureAlgorithm } from './schemas.js'
import type { Verifier } from './verifier.js'

/** How many verified signatures the memo keeps, least recently used evicted first. */
export const VERIFIED_MEMO_SIZE = 8192

/**
 * Messages longer than this are verified every time and never remembered. Signed JWT inputs and
 * record payloads are well under it; the cap keeps a single entry from pinning a large buffer.
 */
export const VERIFIED_MEMO_MAX_MESSAGE_BYTES = 16 * 1024

/**
 * Upper bound on the message bytes held across all entries. With typical sub-kilobyte messages
 * the entry count is the binding limit; this one only matters if many messages approach the cap.
 */
export const VERIFIED_MEMO_MAX_TOTAL_BYTES = 8 * 1024 * 1024

// Module-level, shared by every memoized verifier: callers re-verify the same signature through
// fresh token objects (stored record copies, delegation chains re-checked per request), so a memo
// scoped to anything narrower would rarely hit. Sharing is sound because the key plus the
// byte-equal message check covers the whole input of a pure function — see `memoizeVerifier`.
const verified = new Map<string, Uint8Array>()
let totalBytes = 0

function bytesKey(bytes: Uint8Array): string {
  let out = ''
  for (const byte of bytes) {
    out += String.fromCharCode(byte)
  }
  return out
}

/**
 * The memo key. The public key length is spelled out so the key/signature boundary cannot shift:
 * without it, two different (publicKey, signature) splits of the same bytes would collide.
 */
function memoKey(alg: SignatureAlgorithm, signature: Uint8Array, publicKey: Uint8Array): string {
  return `${alg}:${publicKey.length}:${bytesKey(publicKey)}${bytesKey(signature)}`
}

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false
  }
  return true
}

/** Store `message`, which the caller hands over: it must be a private copy. */
function remember(key: string, message: Uint8Array): void {
  const previous = verified.get(key)
  if (previous !== undefined) {
    // Same signature and key over another message: possible only for a broken verifier or a
    // non-deterministic scheme. Keep the latest, and keep the byte count honest.
    verified.delete(key)
    totalBytes -= previous.length
  }
  verified.set(key, message)
  totalBytes += message.length
  while (verified.size > VERIFIED_MEMO_SIZE || totalBytes > VERIFIED_MEMO_MAX_TOTAL_BYTES) {
    const oldest = verified.entries().next().value
    if (oldest === undefined) break
    verified.delete(oldest[0])
    totalBytes -= oldest[1].length
  }
}

/**
 * Wrap a verifier so a positive result for the exact same (algorithm, public key, signature,
 * message) is answered from a bounded, process-wide memo instead of re-running the curve math.
 *
 * Signature verification is a pure function of (signature, message, public key), so a hit — which
 * requires the message to be byte-equal to the one verified — is exactly as sound as verifying
 * again. Only a strict `true` is remembered: a `false`, a thrown error or a rejected promise is
 * recomputed on every call. Messages over {@link VERIFIED_MEMO_MAX_MESSAGE_BYTES} are never
 * remembered. Works for sync and async verifiers alike; a hit always answers synchronously.
 *
 * The package applies it to its default verifiers only. A verifier supplied through the
 * `verifiers` option is called as given, every time.
 */
export function memoizeVerifier(alg: SignatureAlgorithm, verify: Verifier): Verifier {
  return (signature, message, publicKey) => {
    const cacheable = message.length <= VERIFIED_MEMO_MAX_MESSAGE_BYTES
    const key = cacheable ? memoKey(alg, signature, publicKey) : undefined
    if (key !== undefined) {
      const known = verified.get(key)
      if (known !== undefined && sameBytes(known, message)) {
        // Refreshed, so the least recently *used* entry is the one evicted.
        verified.delete(key)
        verified.set(key, known)
        return true
      }
    }
    const result = verify(signature, message, publicKey)
    if (key === undefined) return result
    // Copied now: the caller may mutate `message` before an async verifier settles.
    if (result instanceof Promise) {
      const copy = message.slice()
      return result.then((ok) => {
        if (ok === true) remember(key, copy)
        return ok
      })
    }
    if (result === true) remember(key, message.slice())
    return result
  }
}

/** Forget every verified signature. Test-only; not exported from the package. */
export function clearVerifiedSignatureMemo(): void {
  verified.clear()
  totalBytes = 0
}

/** How many verified signatures are remembered. Test-only; not exported from the package. */
export function verifiedSignatureMemoSize(): number {
  return verified.size
}
