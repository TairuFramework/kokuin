import { decodeMultibase, encodeMultibase, multihashSHA256, verifyMultihash } from '@kokuin/token'

const encoder = new TextEncoder()

/**
 * Deepest nesting these functions will encode. The top-level value is depth 1, a value inside it
 * depth 2, and so on.
 *
 * `canonicalize` recurses once per level, so without a bound the nesting depth of untrusted input
 * decides how much of the call stack is used: `JSON.parse` is iterative in V8 and accepts
 * unbounded depth, so a few kilobytes of `[[[[…]]]]` on the wire is a `RangeError` here — thrown
 * from a function every event of every log passes through, and from inside `resolveBranches`,
 * where one hostile branch would take duplicity detection down for every well-formed branch
 * beside it.
 *
 * A bound rather than a `try`/`catch` around the recursion. Catching a `RangeError` would turn
 * this particular throw into a reason while still letting an attacker drive the stack to
 * exhaustion once per event — the work is done before the catch, it is unbounded per event, and a
 * stack that deep unwinds through whatever frame happens to be innermost, so the catch would also
 * have to sit at every call site rather than at one. The bound costs a comparison per level and
 * makes the depth of untrusted input irrelevant.
 *
 * 64 is far above anything this stack canonicalizes — an event body reaches depth 3 (`{ k: [ "…" ] }`)
 * — and far below the ~10⁴ frames a JS stack holds. Raising it is safe; lowering it below 3 is not.
 * It never changes the encoding of a value it accepts, so no identifier this stack has issued moves.
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
 * {@link MAX_CANONICAL_DEPTH}.
 *
 * The total counterpart of the bound above: this is what a caller holding untrusted input uses to
 * turn "too deep" into a rejection with a reason instead of an exception. Its own recursion is
 * bounded by the same constant, so it is safe on exactly the input it exists to judge — including
 * a cyclic object, which `canonicalize` cannot be handed from parsed JSON but can be handed by a
 * caller.
 *
 * Answers only the depth question. Prefer {@link isCanonicalizable} for untrusted input: a
 * non-finite number *is* reachable from `JSON.parse` — `1e400` off the wire is `Infinity` — and
 * this predicate says nothing about it.
 */
export function withinCanonicalDepth(value: unknown, depth = 1): boolean {
  // The same comparison at the same point as `canonicalize`'s, so the two agree exactly on the
  // boundary rather than approximately.
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
 * instead of raised.
 *
 * The total counterpart of the whole canonicalizer, and what a caller holding untrusted input uses.
 * {@link withinCanonicalDepth} answers one of the two questions and was for a while the only one
 * asked, which left a hole: `1e400` on the wire parses to `Infinity`, is a `number`, nests no
 * deeper than any other member, and reached `canonicalize` — where it *threw*. `foldLog`,
 * `foldLogAsync` and `verifySignatures` are documented total, so that throw broke their contract,
 * and one hostile branch took `resolveBranches` down for every honest branch beside it.
 *
 * Answers `false` for exactly what `canonicalize` refuses:
 *
 * - a non-finite number — `Infinity`, `-Infinity`, `NaN`. All three are reachable from `JSON.parse`:
 *   the first two from any literal that overflows a double (`1e400`, `-1e400`), and `NaN` from
 *   nothing on the wire but from a caller's own object. A digest cannot name a value with no
 *   encoding, so an event carrying one is malformed rather than unfoldable.
 * - a value of a type with no encoding here — `bigint`, `symbol`, `function`, `undefined` at the
 *   top level. None arrives from `JSON.parse`; all arrive from a caller.
 * - a non-plain object — a class instance, anything with a prototype other than `Object.prototype`
 *   or `null`. `JSON.parse` produces only plain objects and arrays, so this too is a caller's.
 * - a value nesting deeper than {@link MAX_CANONICAL_DEPTH}, which is `withinCanonicalDepth`'s
 *   question and stays answered here so one call covers the whole contract.
 *
 * Two things it deliberately does **not** reject, both documented rather than guarded:
 *
 * - `-0`. It encodes as `0`, which is what JCS and ES6 `Number::toString` prescribe, so `-0` and
 *   `0` share a digest. They are the same value under every comparison anything in this package
 *   makes (`===`, `<`, `+`), and no field the fold reads distinguishes them, so the shared digest
 *   names one value rather than two.
 * - an integer past `Number.MAX_SAFE_INTEGER`. `9007199254740993` and `9007199254740992` are two
 *   wire spellings that `JSON.parse` collapses to one double *before* anything here sees them, so
 *   the shared digest is again one value and not two. Rejecting the collapsed value would refuse
 *   numbers JCS accepts while removing no distinction: this package never trusts wire bytes, it
 *   re-canonicalizes from the parsed value, so there is nothing an attacker can make the two
 *   spellings mean differently.
 *
 * Its own recursion is bounded by the same constant, so it is safe on exactly the input it exists
 * to judge — including a cyclic object, which `JSON.parse` cannot produce but a caller can.
 */
export function isCanonicalizable(value: unknown, depth = 1): boolean {
  // The same comparison at the same point as `canonicalize`'s, so the two agree exactly on the
  // boundary rather than approximately.
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
 * JCS-style canonical bytes: keys sorted lexicographically, no insignificant whitespace,
 * `undefined` properties dropped so an absent optional field never encodes as `null`.
 *
 * The DID is the hash of these bytes, so any change to this function changes every identifier
 * the stack has ever issued. It is effectively frozen.
 *
 * Throws for a value nesting deeper than {@link MAX_CANONICAL_DEPTH}. Callers holding untrusted
 * input reject with {@link withinCanonicalDepth} first rather than catching that.
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
 * throwing.
 *
 * Both halves matter, and only the digest half was total before. The value side is the untrusted
 * one in every real use — "is this the body that digest names" is asked about bytes off the wire —
 * so a value this file cannot encode has to be an answer, not an exception. `false` is the correct
 * answer rather than a convenient one: a digest this package produced can only name a value it
 * could canonicalize, so a value it cannot canonicalize matches no digest it ever issued.
 *
 * {@link isCanonicalizable} rather than {@link withinCanonicalDepth}: depth was only one of the
 * ways `canonicalize` throws, and the other one — a non-finite number — arrives from `JSON.parse`
 * just as readily.
 *
 * `canonicalBytes` keeps the throw. Its contract is "these exact bytes or nothing", and a caller
 * asking for bytes has nothing useful to do with `false`.
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
