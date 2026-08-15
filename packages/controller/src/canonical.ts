import { decodeMultibase, encodeMultibase, multihashSHA256, verifyMultihash } from '@kokuin/token'

const encoder = new TextEncoder()

/**
 * Deepest nesting these functions will encode (top-level value is depth 1). `canonicalize` recurses
 * once per level, so without a bound the depth of untrusted input decides stack use: `JSON.parse` is
 * iterative and accepts unbounded depth, so a few kilobytes of `[[[[…]]]]` on the wire is a
 * `RangeError` thrown from a function every event passes through — and from inside `resolveBranches`,
 * where one hostile branch would take duplicity detection down for every honest one.
 *
 * A bound rather than a `try`/`catch`: catching would still let an attacker drive the stack to
 * exhaustion once per event, and would have to sit at every call site. 64 is far above anything this
 * stack canonicalizes (an event body reaches depth 3) and far below the ~10⁴ frames a JS stack holds.
 * Raising it is safe; lowering below 3 is not. It never changes the encoding of a value it accepts.
 */
export const MAX_CANONICAL_DEPTH = 64

function canonicalize(value: unknown, depth: number): string {
  if (depth > MAX_CANONICAL_DEPTH) {
    throw new Error(`Canonicalization: value nests deeper than ${MAX_CANONICAL_DEPTH}`)
  }
  if (value === null) {
    return 'null'
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) {
      throw new Error('Canonicalization: numbers must be finite')
    }
    return JSON.stringify(value)
  }
  if (typeof value === 'string' || typeof value === 'boolean') {
    return JSON.stringify(value)
  }
  if (Array.isArray(value)) {
    return `[${value.map((entry) => canonicalize(entry, depth + 1)).join(',')}]`
  }
  if (typeof value === 'object') {
    const proto = Object.getPrototypeOf(value)
    if (proto !== Object.prototype && proto !== null) {
      throw new Error('Canonicalization: only plain objects are supported')
    }
    const entries = Object.entries(value as Record<string, unknown>)
      .filter(([, v]) => v !== undefined)
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
      .map(([k, v]) => `${JSON.stringify(k)}:${canonicalize(v, depth + 1)}`)
    return `{${entries.join(',')}}`
  }
  throw new Error(`Canonicalization: unsupported value type ${typeof value}`)
}

/**
 * Whether {@link canonicalBytes} could encode this value without exceeding
 * {@link MAX_CANONICAL_DEPTH} — the total counterpart of the bound above, turning "too deep" into a
 * rejection. Bounded by the same constant, so it is safe even on a cyclic object (which parsed JSON
 * cannot produce but a caller can). Answers only the depth question; prefer {@link isCanonicalizable}
 * for untrusted input, since a non-finite number is reachable from `JSON.parse` and this ignores it.
 */
export function withinCanonicalDepth(value: unknown, depth = 1): boolean {
  // Same comparison at the same point as `canonicalize`'s, so the two agree exactly on the boundary.
  if (depth > MAX_CANONICAL_DEPTH) {
    return false
  }
  if (value == null || typeof value !== 'object') {
    return true
  }
  const entries = Array.isArray(value) ? value : Object.values(value as Record<string, unknown>)
  return entries.every((entry) => withinCanonicalDepth(entry, depth + 1))
}

/**
 * Whether {@link canonicalBytes} could encode this value at all — every reason it throws, answered
 * instead of raised. The total counterpart of the whole canonicalizer. {@link withinCanonicalDepth}
 * answers only depth, which left a hole: `1e400` on the wire parses to `Infinity`, is a `number`,
 * nests no deeper than anything, and reached `canonicalize` where it *threw* — breaking the total
 * contract of `foldLog`/`verifySignatures` and taking `resolveBranches` down for every honest branch.
 *
 * Answers `false` for exactly what `canonicalize` refuses: a non-finite number (`Infinity`/`NaN`,
 * the first reachable from `JSON.parse` via `1e400`); a type with no encoding (`bigint`, `symbol`,
 * `function`, top-level `undefined` — all caller-only); a non-plain object (caller-only); a value
 * nesting past {@link MAX_CANONICAL_DEPTH}, kept here so one call covers the whole contract.
 *
 * Deliberately **not** rejected: `-0` (encodes as `0`, same value under every comparison this package
 * makes), and integers past `Number.MAX_SAFE_INTEGER` (`JSON.parse` collapses the two wire spellings
 * to one double before anything here sees them, so the shared digest names one value). Bounded by the
 * same constant, so it is safe even on a cyclic object.
 */
export function isCanonicalizable(value: unknown, depth = 1): boolean {
  // Same comparison at the same point as `canonicalize`'s, so the two agree exactly on the boundary.
  if (depth > MAX_CANONICAL_DEPTH) {
    return false
  }
  if (value === null) {
    return true
  }
  if (typeof value === 'number') {
    return Number.isFinite(value)
  }
  if (typeof value === 'string' || typeof value === 'boolean') {
    return true
  }
  if (Array.isArray(value)) {
    return value.every((entry) => isCanonicalizable(entry, depth + 1))
  }
  if (typeof value === 'object') {
    const proto = Object.getPrototypeOf(value)
    if (proto !== Object.prototype && proto !== null) {
      return false
    }
    // `undefined` members are dropped by `canonicalize` rather than encoded, so they are not a
    // reason to refuse — mirroring the `filter` there.
    return Object.values(value as Record<string, unknown>).every(
      (entry) => entry === undefined || isCanonicalizable(entry, depth + 1),
    )
  }
  return false
}

/**
 * JCS-style canonical bytes: keys sorted lexicographically, no insignificant whitespace, `undefined`
 * properties dropped so an absent optional field never encodes as `null`. The DID is the hash of
 * these bytes, so any change here moves every identifier the stack has issued — effectively frozen.
 * Throws for a value past {@link MAX_CANONICAL_DEPTH}; untrusted callers reject with
 * {@link withinCanonicalDepth} first.
 */
export function canonicalBytes(value: unknown): Uint8Array {
  return encoder.encode(canonicalize(value, 1))
}

/** Self-addressing digest: multibase(multihash(canonical bytes)). */
export function digestOf(value: unknown): string {
  return encodeMultibase(multihashSHA256(canonicalBytes(value)))
}

/**
 * Total: a malformed digest *or* a value this file cannot canonicalize returns false rather than
 * throwing. The value side is the untrusted one in real use ("is this the body that digest names" is
 * asked about wire bytes), and `false` is correct, not convenient: a digest this package produced can
 * only name a value it could canonicalize. Uses {@link isCanonicalizable}, not
 * {@link withinCanonicalDepth}, since a non-finite number is another way `canonicalize` throws.
 * `canonicalBytes` keeps its throw — its contract is "these exact bytes or nothing".
 */
export function verifyDigest(digest: string, value: unknown): boolean {
  let expected: Uint8Array
  try {
    expected = decodeMultibase(digest)
  } catch {
    return false
  }
  if (!isCanonicalizable(value)) {
    return false
  }
  return verifyMultihash(expected, canonicalBytes(value))
}
