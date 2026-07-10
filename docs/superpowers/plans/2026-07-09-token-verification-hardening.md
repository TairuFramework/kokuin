# Token Verification Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Stage:** executing
**Mode:** tasks
**Spec:** `docs/superpowers/specs/2026-07-09-token-verification-hardening-design.md`

**Goal:** Make `@kokuin/token` safe for a direct consumer standalone — reject `alg:none` tokens by default, make the type guards total, and bound the `did:peer:4` base58 decode.

**Architecture:** Three independent changes inside `packages/token/src`. `verifyToken` gains an `allowUnsigned` option defaulting to `false`, plus overloads so the strict call returns `VerifiedToken<Payload>` (a type that cannot hold an unsigned token) rather than the `Token` union. The three type guards get an object check so they return `false` instead of throwing on nullish input. `decodePeer4` gains a bound on the attacker-controlled hash segment and a tightened bound on the encoded doc.

**Tech Stack:** TypeScript, vitest, `@sozai/schema` validators, `@scure/base` base58, changesets.

## Global Constraints

Copied from `AGENTS.md` and the repo conventions — every task's requirements implicitly include these:

- pnpm only. Never `npm` or `yarn`.
- An `rtk` shim intercepts `pnpm run <script>`. **Always invoke tools directly** (`pnpm exec vitest`, `pnpm exec tsc`, `pnpm exec biome`) rather than `pnpm run <script>`.
- `type` not `interface`. `Array<T>` not `T[]`. Never `any`.
- Capital `ID` / `HTTP` / `JWT` in identifiers.
- ES `#fields`, never `private` / `readonly`.
- Never edit generated files under `lib/`.
- Cross-repo deps (`@sozai/*`) stay published `^` ranges, never `workspace:`.
- **`@kokuin/capability` resolves `@kokuin/token` to its compiled `lib/`, not `src/`** —
  there is no vitest alias. After editing token source, run
  `cd packages/token && rtk proxy pnpm run build` before running the capability suite,
  or it will silently pass against stale code. `lib/` is gitignored; the rebuild is not
  committed. (Discovered during Task 1.)

## File Structure

| File | Responsibility | Tasks |
|---|---|---|
| `packages/token/src/token.ts` | `verifyToken` overloads + `allowUnsigned` gate; total type guards | 1, 2 |
| `packages/token/src/jwe.ts` | `unwrapEnvelope` opts into `allowUnsigned` for `'plain'` | 2 |
| `packages/token/src/peer4.ts` | hash-segment bound; tightened encoded-doc bound | 3 |
| `packages/token/src/did.ts` | bound the `did:key` payload before base58 decode | 4 |
| `packages/capability/src/revocation.ts` | drop a now-redundant cast | 2 |
| `packages/token/test/token.test.ts` | guard totality; `alg:none` gate | 1, 2 |
| `packages/token/test/sign-verify.test.ts` | **invert** the existing "unsigned still verifies" assertion | 2 |
| `packages/token/test/envelope.test.ts` | plain round-trip still works; expired plain rejects | 2 |
| `packages/token/test/peer4.test.ts` | both decode bounds, and that they run before decoding | 3 |
| `packages/token/test/did.test.ts` | `did:key` bound, and that it runs before decoding | 4 |
| `packages/capability/test/lib.test.ts` | `assertCapabilityToken(null)` throws a domain error | 1 |
| `.changeset/token-verification-hardening.md` | release notes | 4 |

---

### Task 1: Total type guards

Make `isSignedToken`, `isUnsignedToken` and `isVerifiedToken` return `false` for any non-object input instead of throwing `TypeError`. This lands first because it has no API surface change and Task 2 relies on `isUnsignedToken` being callable on `unknown`.

**Files:**
- Modify: `packages/token/src/token.ts:114-132`
- Test: `packages/token/test/token.test.ts`
- Test: `packages/capability/test/lib.test.ts`

**Interfaces:**
- Consumes: nothing.
- Produces: `isSignedToken(token: unknown): token is SignedToken<Payload>`, `isUnsignedToken(token: unknown): token is UnsignedToken<Payload>`, `isVerifiedToken(token: unknown): token is VerifiedToken<Payload>` — all total, none throw.

- [x] **Step 1: Write the failing tests**

Append to `packages/token/test/token.test.ts`. `isVerifiedToken` and `isSignedToken` are already imported at the top of that file; `isUnsignedToken` too.

```ts
describe('type guards are total', () => {
  const nonTokens = [null, undefined, '', 0, false, [], 'string', {}]

  for (const value of nonTokens) {
    it(`isSignedToken returns false for ${JSON.stringify(value) ?? 'undefined'}`, () => {
      expect(isSignedToken(value)).toBe(false)
    })

    it(`isUnsignedToken returns false for ${JSON.stringify(value) ?? 'undefined'}`, () => {
      expect(isUnsignedToken(value as never)).toBe(false)
    })

    it(`isVerifiedToken returns false for ${JSON.stringify(value) ?? 'undefined'}`, () => {
      expect(isVerifiedToken(value)).toBe(false)
    })
  }
})
```

Note the `as never` on `isUnsignedToken` — it is needed only until Step 3 widens the parameter to `unknown`. Step 5 removes it.

- [x] **Step 2: Run the tests to verify they fail**

```bash
cd packages/token && pnpm exec vitest run test/token.test.ts -t 'type guards are total'
```

Expected: FAIL. The `null` and `undefined` cases throw `TypeError: Cannot read properties of null (reading 'header')`. The `0`, `false`, `''` and `'string'` cases already pass (property access on a primitive yields `undefined` rather than throwing), so only the nullish ones go red — that is the bug, and it is enough to drive the fix.

- [x] **Step 3: Widen and guard `isSignedToken`**

Replace `packages/token/src/token.ts:114-123` with:

```ts
export function isSignedToken<Payload extends SignedPayload = SignedPayload>(
  token: unknown,
): token is SignedToken<Payload> {
  if (typeof token !== 'object' || token === null) {
    return false
  }
  const t = token as SignedToken<Payload>
  return (
    isType(validateSignedHeader, t.header) &&
    isType(validateSignedPayload, t.payload) &&
    t.signature != null
  )
}
```

- [x] **Step 4: Widen and guard `isUnsignedToken`**

Replace `packages/token/src/token.ts:128-132` with:

```ts
export function isUnsignedToken<Payload extends Record<string, unknown>>(
  token: unknown,
): token is UnsignedToken<Payload> {
  if (typeof token !== 'object' || token === null) {
    return false
  }
  return isType(validateUnsignedHeader, (token as UnsignedToken<Payload>).header)
}
```

`isVerifiedToken` needs no edit: it calls `isSignedToken` first (`token.ts:142`), so it becomes total transitively.

Widening the parameter to `unknown` does not lose negative narrowing at `jwe.ts:311`. TypeScript narrows the false branch from the *variable's* declared type (`Token<Payload>`), not from the predicate's parameter type, so the `else` path still narrows to `SignedToken | VerifiedToken`.

- [x] **Step 5: Drop the `as never` from the test**

In the test written in Step 1, change `isUnsignedToken(value as never)` to `isUnsignedToken(value)`. It now typechecks, and the cast would hide a regression if the parameter were ever narrowed back.

- [x] **Step 6: Run the tests to verify they pass**

```bash
cd packages/token && pnpm exec vitest run test/token.test.ts
```

Expected: PASS, all tests in the file including the pre-existing ones.

- [x] **Step 7: Typecheck the token package**

```bash
cd packages/token && pnpm exec tsc --noEmit --skipLibCheck -p tsconfig.test.json
```

Expected: no output, exit 0.

- [x] **Step 8: Write the failing capability test**

The audit's cited downstream symptom is `assertCapabilityToken(null)` raising `TypeError`. Verify it now raises the domain error. `assertCapabilityToken` is exported from `packages/capability/src/index.ts:172`; check the existing import block at the top of `packages/capability/test/lib.test.ts` and add it there if absent.

```ts
describe('assertCapabilityToken with non-token input', () => {
  it('throws a domain error, not a TypeError', () => {
    expect(() => assertCapabilityToken(null)).toThrow('Invalid token: not a capability')
    expect(() => assertCapabilityToken(undefined)).toThrow('Invalid token: not a capability')
  })
})
```

- [x] **Step 9: Run the capability tests**

```bash
cd packages/token && rtk proxy pnpm run build
cd ../capability && pnpm exec vitest run test/lib.test.ts -t 'assertCapabilityToken with non-token input'
```

Expected: PASS. The rebuild is required — `@kokuin/capability` resolves `@kokuin/token` to its compiled `lib/`, so without it the suite runs against the pre-fix code and still throws `TypeError`. If it fails with `TypeError` *after* a successful rebuild, the Step 3 edit did not land.

- [x] **Step 10: Lint**

```bash
pnpm exec biome check --write ./packages
```

Expected: no errors. Review any file it rewrites.

- [x] **Step 11: Commit**

```bash
git add packages/token/src/token.ts packages/token/test/token.test.ts packages/capability/test/lib.test.ts
git commit -m "fix(token): make type guards total over unknown input

isSignedToken(null) threw TypeError instead of returning false,
propagating to assertCapabilityToken(null). Guard on typeof before
property access, and widen isUnsignedToken to accept unknown."
```

---

### Task 2: Reject `alg:none` by default

**Files:**
- Modify: `packages/token/src/token.ts` — `VerifyTokenOptions` (`:27-40`), both `alg:none` sites (`:204`, `:243`), `verifyTokenInner` destructure (`:202`), `verifyToken` (`:284`)
- Modify: `packages/token/src/jwe.ts:310`
- Modify: `packages/capability/src/revocation.ts:63`
- Test: `packages/token/test/token.test.ts`
- Test: `packages/token/test/sign-verify.test.ts:74`
- Test: `packages/token/test/envelope.test.ts`

**Interfaces:**
- Consumes: `isUnsignedToken(token: unknown)` from Task 1.
- Produces: `VerifyTokenOptions.allowUnsigned?: boolean`; `verifyToken(token, options?)` returning `Promise<VerifiedToken<Payload>>` when `allowUnsigned` is absent or literal `false`, and `Promise<Token<Payload>>` when it is literal `true` or the options argument is a widened `VerifyTokenOptions`.

- [x] **Step 1: Write the failing tests for the gate**

Append to `packages/token/test/token.test.ts`. Add `type Token` to the existing `../src/types.js` type import if you need it; the tests below do not.

```ts
describe('verifyToken rejects alg:none by default', () => {
  const fixedTime = 1700000000

  function unsignedString(payload: Record<string, unknown>, header = { typ: 'JWT', alg: 'none' }) {
    return `${b64uFromJSON(header)}.${b64uFromJSON(payload)}.`
  }

  it('rejects an alg:none token string', async () => {
    await expect(verifyToken(unsignedString({ test: true }))).rejects.toThrow(
      /unsigned tokens rejected/,
    )
  })

  it('rejects an unsigned token object', async () => {
    const unsigned = createUnsignedToken({ test: true })
    await expect(verifyToken(unsigned)).rejects.toThrow(/unsigned tokens rejected/)
  })

  it('accepts an alg:none token string with allowUnsigned', async () => {
    const token = await verifyToken(unsignedString({ test: true }), { allowUnsigned: true })
    expect(isUnsignedToken(token)).toBe(true)
    expect(token.payload).toEqual({ test: true })
  })

  it('accepts an unsigned token object with allowUnsigned', async () => {
    const unsigned = createUnsignedToken({ test: true })
    const token = await verifyToken(unsigned, { allowUnsigned: true })
    expect(token).toBe(unsigned)
  })

  it('rejects a malformed unsigned header even with allowUnsigned', async () => {
    const bad = unsignedString({ test: true }, { typ: 'NOTJWT', alg: 'none' })
    await expect(verifyToken(bad, { allowUnsigned: true })).rejects.toThrow(
      'Invalid token header type',
    )
  })

  it('rejects an expired unsigned token with allowUnsigned', async () => {
    const token = unsignedString({ test: true, exp: fixedTime - 100 })
    await expect(
      verifyToken(token, { allowUnsigned: true, atTime: fixedTime }),
    ).rejects.toThrow('Token expired')
  })

  it('rejects a not-yet-valid unsigned token with allowUnsigned', async () => {
    const token = unsignedString({ test: true, nbf: fixedTime + 100 })
    await expect(
      verifyToken(token, { allowUnsigned: true, atTime: fixedTime }),
    ).rejects.toThrow('Token not yet valid')
  })

  it('honours clockTolerance for an expired unsigned token', async () => {
    const token = unsignedString({ test: true, exp: fixedTime - 100 })
    await expect(
      verifyToken(token, { allowUnsigned: true, atTime: fixedTime, clockTolerance: 200 }),
    ).resolves.toBeDefined()
  })

  it('rejects an unsigned token when an audience is expected, even with allowUnsigned', async () => {
    const token = unsignedString({ test: true, aud: 'did:key:service-a' })
    await expect(
      verifyToken(token, { allowUnsigned: true, audience: 'did:key:service-a' }),
    ).rejects.toThrow(/requires a signed token/)
  })

  it('still verifies a signed token with no options', async () => {
    const identity = randomIdentity()
    const signed = await identity.signToken({ test: true })
    const verified = await verifyToken(stringifyToken(signed))
    expect(isVerifiedToken(verified)).toBe(true)
  })
})
```

The malformed-header case throws `'Invalid token header type'` from the pre-existing `header.typ !== 'JWT'` guard at `token.ts:240`, which runs before the `alg` branch. That guard is the only thing catching it — the spec explicitly declines to add a redundant `assertType` on this path — so this test is load-bearing, not decorative.

Every symbol these tests use is already imported at the top of `token.test.ts`: `b64uFromJSON` from `@sozai/codec`, and `createUnsignedToken` / `isUnsignedToken` / `isVerifiedToken` / `verifyToken` / `randomIdentity` / `stringifyToken` from the source modules. No import edits needed.

- [x] **Step 2: Run the tests to verify they fail**

```bash
cd packages/token && pnpm exec vitest run test/token.test.ts -t 'verifyToken rejects alg:none by default'
```

Expected: exactly four of the ten fail.

| Test | Pre-fix result | Why |
|---|---|---|
| rejects an alg:none token string | **FAIL** | resolves today |
| rejects an unsigned token object | **FAIL** | resolves today |
| rejects an expired unsigned token | **FAIL** | time validation is skipped on the unsigned path |
| rejects a not-yet-valid unsigned token | **FAIL** | same |
| accepts an alg:none token string with allowUnsigned | pass | the option is ignored, and today's behavior already resolves |
| accepts an unsigned token object with allowUnsigned | pass | same |
| rejects a malformed unsigned header | pass | caught by the pre-existing `typ` guard |
| honours clockTolerance | pass | resolves either way |
| rejects unsigned when an audience is expected | pass | `assertSignedForAudience` already throws |
| still verifies a signed token | pass | untouched path |

The six that pass are regression guards, not drivers. Do not "fix" them by making them fail — if any of the four listed as FAIL comes back green, the test is wrong, not the code.

- [x] **Step 3: Add the option and the gate helper**

In `packages/token/src/token.ts`, add to the `VerifyTokenOptions` type (after the `audience` field, `:39`):

```ts
  /**
   * Accept unsigned (`alg:none`) tokens. Defaults to `false`.
   *
   * An unsigned token carries no proof of its claims: its payload is entirely
   * attacker-chosen. With the default, `verifyToken` rejects them and its return type is
   * `VerifiedToken`, so a caller cannot reach an unverified payload by accident. Only opt
   * in when the payload is not used for authorization.
   */
  allowUnsigned?: boolean
```

Add this helper next to `assertSignedForAudience` (after `token.ts:64`):

```ts
function assertUnsignedAllowed(allowUnsigned: boolean): void {
  if (!allowUnsigned) {
    throw new Error('Invalid token: unsigned tokens rejected, pass allowUnsigned to accept')
  }
}
```

- [x] **Step 4: Gate both `alg:none` paths**

In `verifyTokenInner`, change the destructure at `token.ts:202` to pull the new option out (so it does not leak into `timeOptions`):

```ts
  const { verifiers, resolver, cache, audience, allowUnsigned = false, ...timeOptions } = options
```

Replace the object path at `token.ts:204-207`:

```ts
    if (isUnsignedToken(token)) {
      assertSignedForAudience(audience)
      assertUnsignedAllowed(allowUnsigned)
      assertTimeClaimsValid(token.payload as Record<string, unknown>, timeOptions)
      return token
    }
```

Replace the string path at `token.ts:243-246`:

```ts
  if (header.alg === 'none') {
    assertSignedForAudience(audience)
    assertUnsignedAllowed(allowUnsigned)
    const payload = b64uToJSON<Payload>(encodedPayload)
    assertTimeClaimsValid(payload as Record<string, unknown>, timeOptions)
    return { header, payload } as UnsignedToken<Payload>
  }
```

`assertSignedForAudience` stays first in both, so an `audience` requirement rejects an unsigned token even when `allowUnsigned` is set.

Neither path re-validates the unsigned header. The object path already passed `isUnsignedToken`, which asserts the schema. On the string path the `header.typ !== 'JWT'` guard at `:240` plus the `header.alg === 'none'` branch condition together imply `validateUnsignedHeader`.

- [x] **Step 5: Add the `verifyToken` overloads**

Replace the `verifyToken` declaration at `token.ts:284-286` with three overload signatures followed by the unchanged implementation signature and body:

```ts
export async function verifyToken<
  Payload extends Record<string, unknown> = Record<string, unknown>,
>(
  token: Token<Payload> | string,
  options?: VerifyTokenOptions & { allowUnsigned?: false },
): Promise<VerifiedToken<Payload>>
export async function verifyToken<
  Payload extends Record<string, unknown> = Record<string, unknown>,
>(
  token: Token<Payload> | string,
  options: VerifyTokenOptions & { allowUnsigned: true },
): Promise<Token<Payload>>
export async function verifyToken<
  Payload extends Record<string, unknown> = Record<string, unknown>,
>(token: Token<Payload> | string, options: VerifyTokenOptions): Promise<Token<Payload>>
export async function verifyToken<
  Payload extends Record<string, unknown> = Record<string, unknown>,
>(token: Token<Payload> | string, options: VerifyTokenOptions = {}): Promise<Token<Payload>> {
  return withSpan(tokenTracer, KokuinSpanNames.TOKEN_VERIFY, {}, async (span) => {
    const result = await verifyTokenInner(token, options)
    if (isSignedToken(result)) {
      span.setAttribute(
        KokuinAttributeKeys.AUTH_DID,
        (result.payload as Record<string, unknown>).iss as string,
      )
      span.setAttribute(KokuinAttributeKeys.AUTH_ALGORITHM, result.header.alg)
    }
    return result
  })
}
```

The third overload is load-bearing and not obvious. `VerifyTokenOptions` declares `allowUnsigned?: boolean`, so a caller passing a *variable* of that type matches neither of the first two overloads (`boolean` is not assignable to `false`, and the second requires `true`). Without the fallback, such a caller gets a compile error. It returns the safe `Token` union. Every current call site passes an object literal, so they all hit the strict first overload.

`VerifiedToken` is already in the type-only import from `./types.js` at `token.ts:17`. No import edit needed.

The implementation signature returns `Promise<Token<Payload>>` while the first overload promises `Promise<VerifiedToken<Payload>>`. TypeScript permits this: overload implementations are checked loosely against their signatures. The soundness argument is that every non-throwing branch of the strict path produces a verified token — the `isVerifiedToken` early return at `:208`, and the two branches that call `verifySignedPayload` and then attach `verifiedPublicKey` (`:226`, `:266`).

- [x] **Step 6: Run the token tests**

```bash
cd packages/token && pnpm exec vitest run test/token.test.ts -t 'verifyToken rejects alg:none by default'
```

Expected: PASS, all ten tests.

- [x] **Step 7: Run the whole token suite to find the breakage**

```bash
cd packages/token && pnpm exec vitest run
```

Expected: FAIL in two places, both intended.

1. `test/sign-verify.test.ts` — the last assertion of `'audience validation rejects unsigned and alg:none tokens'`.
2. `test/envelope.test.ts` — `'plain mode round-trip'`, because `unwrapEnvelope` does not yet opt in.

- [x] **Step 8: Invert the stale assertion in `sign-verify.test.ts`**

At `packages/token/test/sign-verify.test.ts:74`, this assertion encodes the old, vulnerable behavior:

```ts
    // Without an audience option, unsigned tokens still verify (unchanged behavior).
    await expect(verifyToken(unsigned as never)).resolves.toBeDefined()
```

Replace it with:

```ts
    // Without an audience option, unsigned tokens are still rejected by default.
    await expect(verifyToken(unsigned as never)).rejects.toThrow(/unsigned tokens rejected/)

    // They verify only when the caller explicitly opts in.
    await expect(verifyToken(unsigned as never, { allowUnsigned: true })).resolves.toBeDefined()
```

- [x] **Step 9: Opt `unwrapEnvelope` into unsigned tokens**

`unwrapEnvelope`'s 3-part branch handles `'plain'`, `'jws'` and `'jwe-in-jws'`, so it must accept unsigned tokens. At `packages/token/src/jwe.ts:310`:

```ts
    const token = await verifyToken(message, {
      verifiers: options.verifiers,
      allowUnsigned: true,
    })
```

Leave `jwe.ts:305` (the `jws-in-jwe` branch) alone — it requires a signed token already, and the strict overload is what we want there.

`unwrapEnvelope` stays permissive toward `'plain'` by design: it returns `mode` in its result, so a caller that must not accept plain envelopes checks that. See "Rejected alternatives" in the spec.

- [x] **Step 10: Write the failing envelope test for expired plain**

Append to the `describe` block containing `'plain mode round-trip'` in `packages/token/test/envelope.test.ts`:

```ts
  test('plain mode rejects an expired envelope', async () => {
    const wrapped = await wrapEnvelope('plain', { test: true, exp: 1700000000 - 100 }, {})
    await expect(unwrapEnvelope(wrapped, {})).rejects.toThrow('Token expired')
  })
```

This uses a literal past `exp`, so it does not depend on the current wall clock. `unwrapEnvelope` does not forward `atTime`, so the token must be expired against real `now()` — an `exp` of `1699999900` (November 2023) always is.

- [x] **Step 11: Run the full token suite**

```bash
cd packages/token && pnpm exec vitest run
```

Expected: PASS, including `test/envelope.test.ts` plain round-trip and the new expired-plain test.

- [x] **Step 12: Drop the now-redundant cast in capability**

`verifyToken` now returns `VerifiedToken<RevocationClaims>`, which extends `SignedToken<RevocationClaims>` — the definition of `RevocationRecord`. The cast at `packages/capability/src/revocation.ts:63` is redundant:

```ts
      verified = await verifyToken<RevocationClaims>(record)
```

Leave `revocation.ts:37` alone — it has no cast to remove.

If `tsc` rejects this because `RevocationRecord` is not structurally satisfied by `VerifiedToken`, restore the cast and move on. The cast removal is a tidiness win, not a requirement of the fix.

- [x] **Step 13: Typecheck and test both packages**

```bash
cd packages/token && pnpm exec tsc --noEmit --skipLibCheck -p tsconfig.test.json && pnpm exec vitest run
cd packages/token && rtk proxy pnpm run build
cd ../capability && pnpm exec tsc --noEmit --skipLibCheck -p tsconfig.test.json && pnpm exec vitest run
```

Expected: exit 0, all tests pass. The token rebuild is required before the capability suite — capability consumes the compiled `lib/`, and this task changes `verifyToken`'s runtime behavior, so a stale `lib/` would mask a real break. The capability suite exercises `verifyToken` through `checkCapability` and `checkDelegationChain`; those call sites pass object literals without `allowUnsigned`, so they bind to the strict overload and their return values narrow to `VerifiedToken`.

- [x] **Step 14: Verify no downstream regression in the workspace**

```bash
cd /Users/paul/dev/yulsi/kokuin && pnpm exec turbo run test:types test:unit
```

Expected: all packages pass. `@kokuin/browser`, `@kokuin/deterministic` and `@kokuin/ledger-device` each call `verifyToken` on a signed token string in their tests; those bind to the strict overload and are unaffected.

- [x] **Step 15: Lint**

```bash
pnpm exec biome check --write ./packages
```

- [x] **Step 16: Commit**

```bash
git add packages/token/src/token.ts packages/token/src/jwe.ts packages/token/test/token.test.ts packages/token/test/sign-verify.test.ts packages/token/test/envelope.test.ts packages/capability/src/revocation.ts
git commit -m "fix(token): reject alg:none tokens unless allowUnsigned is set

verifyToken returned unsigned tokens with attacker-chosen claims and
skipped exp/nbf entirely, on both the object and string paths. Gate both
behind allowUnsigned (default false), and validate time claims on the
unsigned path when opted in.

The strict overload now returns VerifiedToken rather than the Token
union, so a consumer that omits an isVerifiedToken check cannot reach an
unverified payload. unwrapEnvelope opts in for its 'plain' mode.

BREAKING: verifyToken rejects alg:none by default and its return type
narrows to VerifiedToken."
```

---

### Task 3: Bound the `did:peer:4` base58 decode

`decodeMultibase` wraps `@scure/base`'s `base58.decode`, an O(n²) big-integer radix conversion. Two unbounded inputs reach it.

**Files:**
- Modify: `packages/token/src/peer4.ts:55` (constants), `:99-105` (bounds)
- Test: `packages/token/test/peer4.test.ts`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: no signature change. `DecodePeer4Options.maxDocSize` keeps its meaning; only the default and the pre-check arithmetic move.

- [x] **Step 1: Write the failing tests**

Append to `packages/token/test/peer4.test.ts`. `decodePeer4` and `encodePeer4` are already imported there.

The base58 alphabet excludes `0`, `O`, `I` and `l`. Building the oversized segments out of `'0'` characters means that if the length check is missing, `base58.decode` throws its own error instead of ours. Asserting on our message therefore proves the bound runs *before* the decode — deterministically, with no mocking and no timing.

```ts
describe('decodePeer4 bounds', () => {
  // 4 KiB default doc + 2 multicodec bytes, times the base58 expansion ratio, plus slack.
  const MAX_ENCODED = Math.ceil((4 * 1024 + 2) * 1.3658) + 8

  const validDoc: DIDDoc = {
    '@context': ['https://www.w3.org/ns/did/v1'],
    verificationMethod: [
      { id: '#key-0', type: 'Multikey', publicKeyMultibase: 'z6MkAbc' },
      { id: '#key-1', type: 'Multikey', publicKeyMultibase: 'z6MkDef' },
      { id: '#key-2', type: 'Multikey', publicKeyMultibase: 'z6MkGhi' },
    ],
    authentication: ['#key-0'],
    keyAgreement: ['#key-1'],
    assertionMethod: ['#key-2'],
  }

  it('rejects an oversized hash segment before decoding it', () => {
    // '0' is not in the base58 alphabet: without the length check, decodeMultibase throws.
    const longForm = `did:peer:4z${'0'.repeat(70)}:z6MkAbc`
    expect(() => decodePeer4(longForm)).toThrow('did:peer:4 hash too large')
  })

  it('rejects an oversized encoded doc before decoding it', () => {
    const hash = `z${'1'.repeat(47)}`
    const encodedDoc = `z${'0'.repeat(MAX_ENCODED)}`
    const longForm = `did:peer:4${hash}:${encodedDoc}`
    expect(() => decodePeer4(longForm)).toThrow(/encoded doc too large/)
  })

  it('decodes a realistic three-key document', () => {
    const { longForm } = encodePeer4(validDoc)
    expect(decodePeer4(longForm).doc).toEqual(validDoc)
  })

  it('honours a smaller maxDocSize override', () => {
    const { longForm } = encodePeer4(validDoc)
    expect(() => decodePeer4(longForm, { maxDocSize: 64 })).toThrow(/too large/)
  })

  it('honours a larger maxDocSize override', () => {
    const { longForm } = encodePeer4(validDoc)
    expect(decodePeer4(longForm, { maxDocSize: 8 * 1024 }).doc).toEqual(validDoc)
  })
})
```

`DIDDoc` is already imported as a type at the top of `peer4.test.ts`.

- [x] **Step 2: Run the tests to verify they fail**

```bash
cd packages/token && pnpm exec vitest run test/peer4.test.ts -t 'decodePeer4 bounds'
```

Expected: FAIL on the two rejection tests, for two different reasons — check the messages, because they are what proves ordering later.

- The hash test throws a `@scure/base` error about a non-base58 character (`0`), from `decodeMultibase(hashEncoded)`, rather than `'did:peer:4 hash too large'`.
- The encoded-doc test throws `'did:peer:4 hash mismatch'`. `MAX_ENCODED` (5606) is far under the current `maxDocSize * 2` pre-check (131072), so the current code sails past it, successfully decodes the 47-character valid-base58 hash, and fails the multihash comparison before ever reaching the doc.

The other three tests are already green. If `'decodes a realistic three-key document'` fails now, the test document is malformed — fix it before proceeding, because Steps 5 and 6 rely on it as the regression guard against a too-tight default.

- [x] **Step 3: Replace the constants**

At `packages/token/src/peer4.ts:55`, replace `const DEFAULT_MAX_DOC_SIZE = 64 * 1024` with:

```ts
const DEFAULT_MAX_DOC_SIZE = 4 * 1024
// base58 expands bytes to characters by log(256) / log(58).
const BASE58_EXPANSION = 1.3658
// A SHA-256 multihash is 34 bytes: 47 base58 characters plus the multibase 'z'.
const MAX_HASH_ENCODED = 64
```

Update the JSDoc on `DecodePeer4Options.maxDocSize` at `:58` — it says "Default 64 KB":

```ts
  /** Maximum allowed size of the canonical doc bytes. Default 4 KiB. */
```

- [x] **Step 4: Add both bounds**

In `decodePeer4`, replace `packages/token/src/peer4.ts:102-105`:

```ts
  const maxSize = options.maxDocSize ?? DEFAULT_MAX_DOC_SIZE
  if (encodedDoc.length > maxSize * 2) {
    throw new Error(`did:peer:4 encoded doc too large: ${encodedDoc.length} > ${maxSize * 2}`)
  }
```

with:

```ts
  // Both segments feed an O(n^2) base58 decode, so bound them before decoding.
  if (hashEncoded.length > MAX_HASH_ENCODED) {
    throw new Error('did:peer:4 hash too large')
  }

  const maxSize = options.maxDocSize ?? DEFAULT_MAX_DOC_SIZE
  const maxEncoded = Math.ceil((maxSize + JSON_MULTICODEC.length) * BASE58_EXPANSION) + 8
  if (encodedDoc.length > maxEncoded) {
    throw new Error(`did:peer:4 encoded doc too large: ${encodedDoc.length} > ${maxEncoded}`)
  }
```

Both checks must precede `decodeMultibase(hashEncoded)` at the following line. `verifyMultihash` already rejects wrong-length multihashes, so `MAX_HASH_ENCODED` rejects nothing that previously succeeded — it is purely a cost bound.

The post-decode `docBytes.length > maxSize` check further down (`:117`) stays. It is the exact bound; `maxEncoded` is the cheap pre-filter.

- [x] **Step 5: Run the tests to verify they pass**

```bash
cd packages/token && pnpm exec vitest run test/peer4.test.ts
```

Expected: PASS, all tests in the file including the pre-existing round-trip tests.

- [x] **Step 6: Run the token and capability suites**

```bash
cd packages/token && pnpm exec vitest run
cd packages/token && rtk proxy pnpm run build
cd ../capability && pnpm exec vitest run
```

Expected: PASS. The token rebuild is required first — capability consumes the compiled `lib/`, so without it the suite would exercise the old unbounded `decodePeer4` and the new bound would go untested. The capability suite mints `did:peer:4` identities; if any test doc exceeds 4 KiB the new default is too tight and the constant needs raising to `8 * 1024` (the spec's stated fallback). Report this rather than silently changing it.

- [x] **Step 7: Typecheck and lint**

```bash
cd packages/token && pnpm exec tsc --noEmit --skipLibCheck -p tsconfig.test.json
cd /Users/paul/dev/yulsi/kokuin && pnpm exec biome check --write ./packages
```

- [x] **Step 8: Commit**

```bash
git add packages/token/src/peer4.ts packages/token/test/peer4.test.ts
git commit -m "fix(token): bound did:peer:4 base58 decode inputs

decodeMultibase wraps an O(n^2) base58 decode. decodePeer4 admitted an
encoded doc of up to maxDocSize * 2 = 128 KiB, and decoded the
attacker-controlled hash segment with no length check at all, so every
inbound token with a long-form did:peer:4 issuer paid the cost.

Drop the default doc size to 4 KiB, replace the arbitrary 2x encoded
pre-check with the real base58 expansion ratio, and bound the hash
segment at 64 characters. Both checks run before any decode."
```

---

### Task 4: Bound the `did:key` base58 decode

Added after the Task 3 review found the same O(n^2) `@scure/base` defect on a sibling path.
`getSignatureInfo` (`packages/token/src/did.ts:54`) calls `base58.decode` on the whole
`did:key` payload with no length bound; the only size check (`did.ts:66`, on the decoded
public key) runs *after* the decode and so cannot prevent the DoS.

This path is **more** reachable than the `did:peer:4` one Task 3 fixed. Traced:

```
verifyToken(untrusted token string)
  -> verifySignedPayload            (token.ts:100)
  -> resolveIssuerWithDoc(payload.iss)  (token.ts:109)
  -> non-peer4 branch               (did.ts:115)
  -> getSignatureInfo(iss)          (did.ts:54)  -> unbounded base58.decode
```

Every step runs **before** the signature check at `token.ts:116`, on the fully
attacker-controlled `iss` claim. `jwe.ts:140` reaches it too, via `recipient`.

**Files:**
- Modify: `packages/token/src/did.ts:54-59`
- Test: `packages/token/test/did.test.ts` (create if absent; check first)

**Interfaces:**
- Consumes: nothing.
- Produces: `getSignatureInfo` throws before decoding when the payload is over-long.

- [ ] **Step 1: Write the failing tests**

`PREFIX` is `'did:key:z'` — it already includes the multibase `z`, so `did.slice(PREFIX.length)`
is pure base58. Build the oversized payload from `'0'`, which is **not** in the base58
alphabet: if the length check is missing or runs after the decode, the test sees
`@scure/base`'s "invalid character" error rather than the intended bound error. That is the
mock-free ordering proof, the same technique Task 3 used.

```ts
test('rejects an over-long did:key before decoding', () => {
  const did = `did:key:z${'0'.repeat(5_000_000)}`
  expect(() => getSignatureInfo(did)).toThrow('Invalid DID format: key too large')
})

test('accepts a maximum-size legitimate did:key', () => {
  // ES256 is the largest supported: 2-byte codec + 33-byte key = 48 base58 chars.
  const publicKey = new Uint8Array(33).fill(0xff)
  const did = getDID(CODECS.ES256, publicKey)
  expect(did.length - 'did:key:z'.length).toBe(48)
  expect(() => getSignatureInfo(did)).not.toThrow()
})
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
cd packages/token && pnpm exec vitest run test/did.test.ts
```

Expected: the first test FAILS. It either hangs for a long time then errors, or throws
`@scure/base`'s invalid-character error — **not** `'Invalid DID format: key too large'`.
The second test PASSES already; it is a regression guard against an over-tight bound.
If the first test errors instantly with the alphabet message, that still counts as a
correct FAIL for this step: the bound does not exist yet.

- [ ] **Step 3: Add the bound**

Only two algorithms are supported (`CODECS`, `did.ts:9`): EdDSA is `2 + 32 = 34` bytes and
ES256 is `2 + 33 = 35` bytes, encoding to 47 and 48 base58 characters respectively
(measured, not estimated). 64 leaves slack for a future codec without admitting a payload
large enough to matter, and matches `MAX_HASH_ENCODED` in `peer4.ts`.

Add near the other constants at the top of `did.ts`:

```ts
// ES256 is the largest supported did:key payload: a 2-byte codec plus a 33-byte key
// encodes to 48 base58 characters. Bound before decoding — base58.decode is O(n^2).
const MAX_DID_KEY_ENCODED = 64
```

Then in `getSignatureInfo`, bound the slice before it reaches `base58.decode`:

```ts
export function getSignatureInfo(did: string): [SignatureAlgorithm, Uint8Array] {
  if (!did.startsWith(PREFIX)) {
    throw new Error('Invalid DID format')
  }

  const encoded = did.slice(PREFIX.length)
  if (encoded.length > MAX_DID_KEY_ENCODED) {
    throw new Error('Invalid DID format: key too large')
  }

  const bytes = base58.decode(encoded)
  // ...rest unchanged
```

Leave the existing post-decode `publicKey.length !== expectedSize` check at `did.ts:66`
alone — it validates a different property (exact key size per algorithm) and is still needed.

- [ ] **Step 4: Run the tests to verify they pass**

```bash
cd packages/token && pnpm exec vitest run test/did.test.ts
```

Expected: PASS. The first test must throw `'Invalid DID format: key too large'` — if it
throws `@scure/base`'s alphabet error instead, the check is in the wrong place. Do not
loosen the assertion to accommodate it.

- [ ] **Step 5: Confirm the DoS is actually closed end to end**

The unit test bounds `getSignatureInfo`. Confirm the *reachable* path is closed too, since
that is the finding: a token whose `iss` is an over-long `did:key` must reject fast rather
than hang.

```bash
cd packages/token && pnpm exec vitest run
```

Expected: PASS, whole suite. Then reason about `verifyToken`: the bound sits upstream of
the signature check, so an over-long `iss` is now rejected before any expensive work.

- [ ] **Step 6: Typecheck, rebuild, and run both suites**

```bash
cd packages/token && pnpm exec tsc --noEmit --skipLibCheck -p tsconfig.test.json
cd packages/token && rtk proxy pnpm run build
cd ../capability && pnpm exec vitest run
```

Expected: exit 0 throughout. The token rebuild is mandatory — capability consumes the
compiled `lib/`. The capability suite mints real `did:key` issuers; if any legitimate DID
now trips the bound, the constant is too tight. Report that rather than raising it silently.

- [ ] **Step 7: Lint**

```bash
cd /Users/paul/dev/yulsi/kokuin && pnpm exec biome check packages/token/src/did.ts packages/token/test/did.test.ts
```

- [ ] **Step 8: Commit**

```bash
git add packages/token/src/did.ts packages/token/test/did.test.ts
git commit -m "fix(token): bound the did:key base58 decode

getSignatureInfo decoded the entire did:key payload with @scure/base's
O(n^2) base58 before checking any size, and the only length check ran
against the already-decoded key. resolveIssuerWithDoc reaches it from
verifyToken with the attacker-controlled iss claim, before the signature
is checked, so an over-long did:key hung the verifier pre-auth.

Bound the encoded payload at 64 characters before decoding. The largest
supported key, ES256, encodes to 48."
```

---

### Task 5: Changeset

**Files:**
- Create: `.changeset/token-verification-hardening.md`

**Interfaces:**
- Consumes: the public-surface changes from Tasks 1-4.
- Produces: nothing consumed by later tasks.

- [ ] **Step 1: Write the changeset**

`.changeset/config.json` has `"fixed": []`, so each package is listed explicitly. `@kokuin/token` takes `minor` — under semver-for-0.x both the strict default and the narrowed return type are breaking. `@kokuin/capability` takes `patch`: only the dropped cast changed, and only if Task 2 Step 12 succeeded. If that step was reverted, omit the capability line entirely.

The changeset must describe **four** fixes, not three: the `alg:none` default (Task 2), the total type guards (Task 1), and the bounded base58 decode on **both** the `did:peer:4` path (Task 3) and the `did:key` path (Task 4). Do not write a blanket "bounded the base58 DoS" line that silently rests on Task 4 having landed — if Task 4 was skipped, say explicitly that `did:key` remains unbounded.

Follow the style of the existing `.changeset/capability-authorization-fixes.md`.

```markdown
---
"@kokuin/token": minor
"@kokuin/capability": patch
---

Harden token verification against unsigned tokens, nullish input, and decode denial of service:

- `verifyToken` now rejects `alg:none` tokens unless the caller passes `allowUnsigned: true`, and validates `exp` / `nbf` on the unsigned path when it does. Without the option its return type narrows to `VerifiedToken`, so a consumer cannot reach an unverified payload without an explicit opt-in.
- `isSignedToken`, `isUnsignedToken` and `isVerifiedToken` accept `unknown` and return `false` for nullish input instead of throwing `TypeError`.
- `decodePeer4` bounds both base58 inputs before decoding: the default `maxDocSize` drops from 64 KiB to 4 KiB, the encoded pre-check uses the real base58 expansion ratio rather than an arbitrary `2x`, and the previously unbounded hash segment is capped.

BREAKING: `verifyToken` rejects `alg:none` tokens by default; pass `allowUnsigned: true` to restore the old behavior. Its return type is now `VerifiedToken<Payload>` rather than `Token<Payload>` unless `allowUnsigned` is set. The default `did:peer:4` document size limit is 4 KiB, down from 64 KiB.
```

- [ ] **Step 2: Verify the changeset parses**

```bash
cd /Users/paul/dev/yulsi/kokuin && pnpm exec changeset status
```

Expected: it lists `@kokuin/token` as `minor` and `@kokuin/capability` as `patch`. A parse error names the offending file.

- [ ] **Step 3: Full verification before handing off**

```bash
cd /Users/paul/dev/yulsi/kokuin && pnpm exec turbo run test:types test:unit
```

Expected: every package passes. Paste the summary line into the commit or the review, per `superpowers:verification-before-completion` — do not claim green without it.

- [ ] **Step 4: Commit**

```bash
git add .changeset/token-verification-hardening.md
git commit -m "chore(token): add changeset for verification hardening"
```

---

## Verification

The plan is complete when:

1. `pnpm exec turbo run test:types test:unit` passes from the repo root.
2. `verifyToken` on an `alg:none` token rejects, on both the object and the string path.
3. `verifyToken(signedToken)` typechecks as `VerifiedToken<Payload>` with no cast.
4. All three type guards return `false` for `null` and `undefined`.
5. `decodePeer4` rejects an oversized hash segment and an oversized encoded doc, each before any base58 decode.
6. `.changeset/token-verification-hardening.md` exists and `pnpm exec changeset status` parses it.
