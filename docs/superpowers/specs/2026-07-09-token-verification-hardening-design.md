# Token verification hardening — design

**Origin:** `docs/agents/plans/next/2026-07-02-token-verification-hardening.md`, itself
extracted from `docs/agents/plans/completed/2026-07-02-audit.complete.md`
(Critical #3, Medium: nullish guards, peer:4 DoS).

## Problem

`@kokuin/token` is a public primitive: `@kokuin/capability`, `@enkaku/server` and any
direct consumer call `verifyToken` and trust its result. Three defects make that trust
unsafe.

1. **`verifyToken` returns `alg:none` tokens as success.** Both the object path
   (`packages/token/src/token.ts:204`) and the string path (`:243`) return early with the
   attacker-supplied payload, skipping signature verification and `exp`/`nbf` validation
   entirely. `@kokuin/capability` happens to be shielded by an `isVerifiedToken` check
   (`packages/capability/src/index.ts:144`), and `@enkaku/server` by an `isSignedToken`
   pre-guard (`packages/server/src/server.ts:496`), but a consumer that does neither is
   spoofable by any unsigned token.
2. **Type guards throw on nullish input.** `isSignedToken(null)`
   (`packages/token/src/token.ts:114`) accesses `.header` on the cast value and raises
   `TypeError` instead of returning `false`. This propagates to
   `assertCapabilityToken(null)`.
3. **`did:peer:4` decoding is an unbounded quadratic.** `decodeMultibase` wraps
   `@scure/base`'s `base58.decode`, an O(n²) big-integer radix conversion.
   `decodePeer4` admits an encoded doc of up to `maxDocSize * 2` = 128 KiB
   (`packages/token/src/peer4.ts:103`), and decodes the hash segment with **no length
   check at all** (`:107`). Every inbound token with a long-form `did:peer:4` issuer pays
   this cost.

## Non-goals

- The capability authorization model — `kid`, `aud`, revocation. Tracked in
  `docs/agents/plans/next/2026-07-02-capability-authorization-fixes.md`.
- Gating `unwrapEnvelope` against `'plain'` envelopes. See "Rejected alternatives".

## 1. `verifyToken` rejects `alg:none` by default

`VerifyTokenOptions` gains `allowUnsigned?: boolean`, defaulting to `false`. `verifyToken`
becomes an overload set:

```ts
export async function verifyToken<Payload extends Record<string, unknown> = Record<string, unknown>>(
  token: Token<Payload> | string,
  options?: VerifyTokenOptions & { allowUnsigned?: false },
): Promise<VerifiedToken<Payload>>
export async function verifyToken<Payload extends Record<string, unknown> = Record<string, unknown>>(
  token: Token<Payload> | string,
  options: VerifyTokenOptions & { allowUnsigned: true },
): Promise<Token<Payload>>
export async function verifyToken<Payload extends Record<string, unknown> = Record<string, unknown>>(
  token: Token<Payload> | string,
  options: VerifyTokenOptions,
): Promise<Token<Payload>>
```

The third overload exists because `VerifyTokenOptions` itself declares
`allowUnsigned?: boolean`. A caller passing a *variable* of that type — rather than an
object literal — matches neither of the first two (`boolean` is not assignable to `false`,
and the second demands `true`), and would otherwise fail to compile. The fallback returns
the safe `Token` union. Every call site in this repo and in `@enkaku` passes an object
literal, so they all bind to the strict first overload.

The narrowed return type of the strict overload is what closes the vulnerability. A
consumer that forgets to call `isVerifiedToken` can no longer reach an attacker-controlled
payload, because the returned type has no unsigned member. The plan item's "document the
requirement to check `isVerifiedToken`" therefore becomes a JSDoc note rather than the
load-bearing mitigation.

This is sound because every non-throwing branch of the strict path already produces a
verified token: the `isVerifiedToken` early-return at `token.ts:208`, and the two branches
that call `verifySignedPayload` and then add `verifiedPublicKey` (`:226`, `:266`).

Both `alg:none` sites get the same treatment — gate, then validate time claims. The string
path at `token.ts:243`:

```ts
if (header.alg === 'none') {
  assertSignedForAudience(audience)
  if (!allowUnsigned) {
    throw new Error('Invalid token: unsigned tokens rejected, pass allowUnsigned to accept')
  }
  const payload = b64uToJSON<Payload>(encodedPayload)
  assertTimeClaimsValid(payload as Record<string, unknown>, timeOptions)
  return { header, payload } as UnsignedToken<Payload>
}
```

The object path at `token.ts:204`, which reaches its early return through
`isUnsignedToken(token)`:

```ts
if (isUnsignedToken(token)) {
  assertSignedForAudience(audience)
  if (!allowUnsigned) {
    throw new Error('Invalid token: unsigned tokens rejected, pass allowUnsigned to accept')
  }
  assertTimeClaimsValid(token.payload as Record<string, unknown>, timeOptions)
  return token
}
```

Neither path re-validates the unsigned header. The object path already went through
`isUnsignedToken`, which asserts the schema. On the string path the existing
`header.typ !== 'JWT'` guard at `token.ts:240` and the `header.alg === 'none'` branch
condition together imply `validateUnsignedHeader`, so an `assertType` there would be a
no-op.

`assertSignedForAudience` stays first, so an `audience` requirement rejects an unsigned
token even when `allowUnsigned` is set — an unsigned token carries no proof of its `aud`.

Validating time claims is a deliberate behavior change beyond the plan item's letter. An
unsigned token's `exp` is attacker-controlled and proves nothing, but honoring it costs
nothing and stops an expired plain envelope from being silently accepted.

### Call sites

All within this repo.

| Site | Change |
|---|---|
| `packages/token/src/jwe.ts:305` (`jws-in-jwe`) | none — a signed token is already required |
| `packages/token/src/jwe.ts:310` (3-part branch) | pass `allowUnsigned: true` |
| `packages/capability/src/index.ts:209,356,411` | none — strict is the desired behavior; the `isVerifiedToken` check at `:144` stays as defense in depth |
| `packages/capability/src/revocation.ts:37,63` | the `as RevocationRecord` casts can drop |

`@enkaku/server` pre-guards with `isSignedToken` before calling `verifyToken`
(`packages/server/src/server.ts:496`), so the tightened default changes no behavior
downstream.

## 2. Total type guards

All three guards accept `unknown` and return `false` for any non-conforming value,
including nullish and primitives.

```ts
export function isSignedToken<Payload extends SignedPayload = SignedPayload>(
  token: unknown,
): token is SignedToken<Payload> {
  if (typeof token !== 'object' || token === null) return false
  const t = token as SignedToken<Payload>
  return (
    isType(validateSignedHeader, t.header) &&
    isType(validateSignedPayload, t.payload) &&
    t.signature != null
  )
}
```

`isVerifiedToken` (`token.ts:138`) delegates to `isSignedToken` first, so it becomes total
with no edit of its own.

`isUnsignedToken` (`token.ts:128`) is declared `token: Token<Payload>`, so a TypeScript
caller cannot pass `null` today, but a JavaScript consumer or an `unknown` cast still
reaches `token.header` and throws. Its parameter widens to `unknown` and it gains the same
object check. Widening does not lose negative narrowing at `jwe.ts:311`: TypeScript narrows
the false branch from the variable's declared type (`Token<Payload>`), not from the
predicate's parameter type, so the `else` path still narrows to
`SignedToken | VerifiedToken`.

The audit's cited downstream symptom — `assertCapabilityToken(null)` raising `TypeError`
rather than a domain error — is fixed transitively. No change is needed in
`@kokuin/capability`, but the behavior gains a test there.

## 3. `did:peer:4` decode bounds

Two changes in `decodePeer4` (`packages/token/src/peer4.ts`).

### The doc bound

`DEFAULT_MAX_DOC_SIZE` drops from `64 * 1024` to `4 * 1024`. The encoded pre-check at
`:103` replaces the arbitrary `maxSize * 2` with the true base58 expansion ratio,
`log(256) / log(58) ≈ 1.3658`:

```ts
const DEFAULT_MAX_DOC_SIZE = 4 * 1024
const BASE58_EXPANSION = 1.3658 // log(256) / log(58)

const maxEncoded = Math.ceil((maxSize + JSON_MULTICODEC.length) * BASE58_EXPANSION) + 8
if (encodedDoc.length > maxEncoded) {
  throw new Error(`did:peer:4 encoded doc too large: ${encodedDoc.length} > ${maxEncoded}`)
}
```

`JSON_MULTICODEC.length` accounts for the two prefix bytes carried inside the base58
payload; the `+ 8` covers the multibase `z` character and rounding. Worst-case decode
input falls from 128 KiB to roughly 5.6 KiB. Because the cost is quadratic, that is about
a 500x reduction in worst-case work. The post-decode `docBytes.length > maxSize` check at
`:117` remains the exact bound.

A realistic `did:peer:4` document with three verification methods is well under 1 KiB, so
4 KiB leaves ample headroom.

### The hash bound

`peer4.ts:107` calls `decodeMultibase(hashEncoded)` with no length check. `hashEncoded` is
`longForm.slice(PEER4_PREFIX.length, sep)` — everything between `did:peer:4` and the next
`:`, entirely attacker-controlled. A `did:peer:4z<500 KB of base58>:x` inflicts the full
quadratic cost before the doc-size check is ever reached, so bounding only `maxDocSize`
would leave the denial of service reachable through a second door. This gap is not in the
original audit.

A SHA-256 multihash is 34 bytes, encoding to 47 base58 characters plus the multibase `z`:

```ts
const MAX_HASH_ENCODED = 64

if (hashEncoded.length > MAX_HASH_ENCODED) {
  throw new Error('did:peer:4 hash too large')
}
```

Placed before the `decodeMultibase(hashEncoded)` call. `verifyMultihash` already rejects
wrong-length multihashes, so this is purely a cost bound and rejects nothing that
previously succeeded.

`DecodePeer4Options.maxDocSize` remains a caller override. Note that `did.ts:96` calls
`decodePeer4(iss)` with no options, so on the token-verification path the default *is* the
bound. Lowering the default is what protects `verifyToken`; there is no plumbing to add.

## Error handling

Every new rejection throws `Error` with a message prefixed `Invalid token:` or
`did:peer:4`, matching the surrounding style. Nothing is caught and swallowed. The
`alg:none` message names the option so the fix is discoverable from the error alone.

## Testing

Tests extend the existing suites rather than adding files.

**`packages/token/test/token.test.ts`** — the `alg:none` gate:

- Strict default rejects an `alg:none` token string.
- Strict default rejects an unsigned token object. (Separate code path; needs its own test.)
- `allowUnsigned: true` returns the unsigned token, on both paths.
- `allowUnsigned: true` with a malformed unsigned header (`typ` not `'JWT'`) rejects,
  covering the `typ` guard that the removed `assertType` would otherwise have shadowed.
- `allowUnsigned: true` with `exp` in the past rejects; with `nbf` in the future rejects;
  `clockTolerance` still applies. Proves `assertTimeClaimsValid` runs.
- `allowUnsigned: true` combined with `audience` rejects.
- A signed token still verifies unchanged with no options.

Guard totality, same file: `isSignedToken`, `isUnsignedToken` and `isVerifiedToken` each
over `null`, `undefined`, `''`, `0`, `false`, `[]`, `'string'` and `{}` — every case
returns `false` and none throws.

**`packages/capability/test/lib.test.ts`** — `assertCapabilityToken(null)` throws its
domain error, not `TypeError`.

**`packages/token/test/peer4.test.ts`**:

- An encoded doc longer than `maxEncoded` rejects *before* decoding.
- An oversized `hashEncoded` segment rejects before `decodeMultibase(hashEncoded)`.
- A realistic document with three verification methods still decodes. This is the
  regression guard against the 4 KiB default being too tight.
- An explicit `maxDocSize` override is honored in both directions.

Ordering is proven without mocks or timing. The oversized segments are built from `'0'`
characters, which are not in the base58 alphabet, so if a length check were missing
`base58.decode` would throw its own error instead. Asserting on our message therefore
establishes that the bound ran first.

**`packages/token/test/envelope.test.ts`** — `wrapEnvelope` / `unwrapEnvelope` live in
`src/jwe.ts` but are exercised from `envelope.test.ts`:

- The `'plain'` envelope round-trip still works, proving the internal `allowUnsigned: true`
  is wired.
- An expired plain envelope throws, proving time validation reaches it.

## Release

A changeset carrying a `minor` bump for `@kokuin/token`: under semver-for-0.x both the
strict default and the narrowed `verifyToken` return type are breaking. `@kokuin/capability`
takes a `patch` — only the dropped casts change. The fixed release group (`token`,
`capability`, `browser`, `node`, `deterministic`) releases together as usual.

## Rejected alternatives

**Splitting `verifyToken` into a strict function plus a separate `parseUnsignedToken`.**
The cleanest boundary, but it churns the public surface for one internal caller
(`jwe.ts`), and the overload pair already gives the strict caller a type that cannot hold
an unsigned token.

**An `algorithms` allowlist (`['EdDSA', 'ES256', 'none']`) instead of a boolean.** More
general — it would also let a caller pin EdDSA-only — but algorithm pinning is a distinct
concern from the `alg:none` bypass, and conflating them makes the security-relevant
default harder to read. Revisit if per-algorithm policy is ever needed.

**Gating `unwrapEnvelope` against `'plain'` envelopes.** `unwrapEnvelope` already returns
`mode` in its result, so a caller that must not accept plain envelopes can check it.
Default-rejecting would break the existing plain round-trip contract for no security gain
inside this repo, and no external consumer calls it.
