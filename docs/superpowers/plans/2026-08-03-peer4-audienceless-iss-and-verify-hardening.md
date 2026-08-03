# `did:peer:4` Audience-Less Issuers and Verification Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Stage:** executing
**Mode:** tasks
**Spec:** `docs/superpowers/specs/2026-08-03-peer4-audienceless-iss-and-verify-hardening-design.md`
**Branch:** `fix/peer4-audienceless-iss-and-verify-hardening`

**Goal:** Make a `did:peer:4` identity's audience-less tokens self-resolving, and close three
deferred token-verification hardening findings that live in the same files.

**Architecture:** One behavioural change plus three guards. `pickIss` in
`packages/token/src/identity.ts` returns the long form whenever the signed payload names no single
string audience, so `createRevocationRecord` and `createRotationAssertion` become verifiable without
changing either of them. `verifyToken`'s already-verified fast path re-binds the payload to the
signed bytes instead of trusting object identity alone. `assertDocWithinMaxSize` gains an O(1)
entry-count pre-guard before its linear serialization, and the in-memory DID cache applies the same
bound before encoding a resolver-supplied document.

**Tech Stack:** TypeScript (ESM, `.js` import specifiers), vitest, pnpm workspaces, biome,
changesets. Crypto via `@noble/curves`; codecs via `@sozai/codec`; schemas via `@sozai/schema`.

## Global Constraints

- pnpm only. Never npm or yarn.
- Run repo scripts as `rtk proxy pnpm run <script>`, or invoke the tool directly
  (`pnpm exec biome check ...`). A bare `pnpm run <script>` may be intercepted by a local shim.
- Per-package unit tests: `pnpm --filter <pkg> exec vitest run <relative test path>`.
- Per-package type tests: `pnpm --filter <pkg> exec tsc --noEmit --skipLibCheck -p tsconfig.test.json`.
- Every relative import inside `src/` and `test/` carries a `.js` extension, including when the
  source file is `.ts`. Follow the existing files exactly.
- Cross-repo deps (`@sozai/*`) stay published `^` ranges, never `workspace:`.
- Do not reformat untouched code. `biome` runs in the pre-commit hook; let it fix its own findings.
- The pre-commit hook runs biome plus `pnpm run -r build:types`. A commit that fails type checking
  will be rejected — fix rather than bypass.
- `MIN_VERIFICATION_METHOD_BYTES` is exactly `40`. `DEFAULT_MAX_DOC_SIZE` stays `4 * 1024`.

---

## File Structure

| File | Responsibility | Task |
|------|----------------|------|
| `packages/token/src/identity.ts` | `pickIss` long-form policy; `SignTokenOptions` JSDoc | 1 |
| `packages/token/test/identity.test.ts` | first-per-aud and audience-less `iss` policy tests | 1 |
| `packages/token/test/rotation.test.ts` | rotation assertion inherits the fix | 1 |
| `packages/capability/test/revocation.test.ts` | the reported reproduction, end to end | 2 |
| `packages/token/src/token.ts` | verified-token fast path re-binds to signed bytes | 3 |
| `packages/token/test/token.test.ts` | mutation and missing-`data` rejection | 3 |
| `packages/token/src/peer4.ts` | O(1) entry-count pre-guard in `assertDocWithinMaxSize` | 4 |
| `packages/token/test/peer4.test.ts` | pre-guard bounds and cap scaling | 4 |
| `packages/token/src/cache.ts` | bound a resolver doc before encoding it | 5 |
| `packages/token/test/cache.test.ts` | oversized-doc rejection on `set` | 5 |
| `.changeset/peer4-audienceless-iss.md` | release note for `@kokuin/token` | 6 |

No source file changes in `@kokuin/capability` — its fix arrives through the token dependency.

---

### Task 1: `pickIss` embeds the long form for audience-less payloads

**Files:**
- Modify: `packages/token/src/identity.ts:18-30` (JSDoc), `packages/token/src/identity.ts:367-381` (`pickIss`)
- Test: `packages/token/test/identity.test.ts` (modify one existing test, add three)
- Test: `packages/token/test/rotation.test.ts` (add one)

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: the rule later tasks and downstream repos rely on — for a `did:peer:4`
  `MultiKeyIdentity`, `signToken(payload)` sets `payload.iss` to `identity.longForm` whenever
  `typeof payload.aud !== 'string'`, unless `options.embedLongForm === false`. Signature of
  `signToken` is unchanged: `signToken<Payload>(payload: Payload, options?: SignTokenOptions):
  Promise<SignedToken<Payload>>`.

- [ ] **Step 1: Rewrite the existing audience-less test to assert the new behaviour**

In `packages/token/test/identity.test.ts`, inside
`describe('MultiKeyIdentity.signToken first-per-aud long-form policy', ...)`, replace this existing
test:

```ts
  it('uses short form by default when payload has no aud', async () => {
    const identity = await createIdentity({
      keys: [{ purpose: 'sig', alg: 'EdDSA' }],
      didMethod: 'peer:4',
    })
    const t = await identity.signToken({ sub: identity.id })
    expect(t.payload.iss).toBe(identity.id)
  })
```

with:

```ts
  it('uses long form when the payload has no aud', async () => {
    const identity = await createIdentity({
      keys: [{ purpose: 'sig', alg: 'EdDSA' }],
      didMethod: 'peer:4',
    })
    const t = await identity.signToken({ sub: identity.id })
    expect(t.payload.iss).toBe(identity.longForm)
  })
```

- [ ] **Step 2: Add the three remaining tests in the same describe block**

```ts
  it('uses long form when aud is an array rather than a single DID', async () => {
    const identity = await createIdentity({
      keys: [{ purpose: 'sig', alg: 'EdDSA' }],
      didMethod: 'peer:4',
    })
    const t = await identity.signToken({ sub: identity.id, aud: ['did:example:bob'] })
    expect(t.payload.iss).toBe(identity.longForm)
  })

  it('embedLongForm:false still forces short form on an audience-less payload', async () => {
    const identity = await createIdentity({
      keys: [{ purpose: 'sig', alg: 'EdDSA' }],
      didMethod: 'peer:4',
    })
    const t = await identity.signToken({ sub: identity.id }, { embedLongForm: false })
    expect(t.payload.iss).toBe(identity.id)
  })

  it('an audience-less token from a multi-key identity verifies with no resolver and no cache', async () => {
    // Two keys means chooseMethod picks peer:4 on its own — the trap door this fixes.
    const identity = await createIdentity({
      keys: [
        { purpose: 'sig', alg: 'EdDSA' },
        { purpose: 'kem', alg: 'X25519' },
      ],
    })
    const t = await identity.signToken({ sub: identity.id })
    await expect(verifyToken(t)).resolves.toBeDefined()
  })
```

`verifyToken` and `createIdentity` are already imported at the top of this file — do not add imports.

- [ ] **Step 3: Run the tests to verify they fail**

Run: `pnpm --filter @kokuin/token exec vitest run test/identity.test.ts`

Expected: FAIL, three tests. Two report the short form (`did:peer:4z…` with no `:` segment) where
the long form was expected; the third throws `Unknown DID: did:peer:4z…` from `verifyToken`. The
`embedLongForm:false` test passes already — it is a regression guard for the escape hatch.

- [ ] **Step 4: Change the `pickIss` branch**

In `packages/token/src/identity.ts`, inside `buildIdentity`:

```ts
  function pickIss(
    payload: Record<string, unknown>,
    embedLongForm: boolean | undefined,
  ): DIDString {
    if (!isPeer) return id
    if (embedLongForm === true) return longForm
    if (embedLongForm === false) return id
    const aud = payload.aud
    // No single named audience: there is nothing to key first-contact on, and the recipient may
    // never have seen this doc. Embed the long form so the token resolves standalone.
    if (typeof aud !== 'string') return longForm
    const normalizedAud = normalizeDID(aud)
    if (sentTo.has(normalizedAud)) return id
    // Concurrent sign() calls with the same new aud may both emit long-form; recipient cache writes are idempotent so this is acceptable.
    sentTo.add(normalizedAud)
    return longForm
  }
```

Only the `typeof aud !== 'string'` line and its comment change. Leave the rest byte-identical.

- [ ] **Step 5: Update the `SignTokenOptions.embedLongForm` JSDoc**

In `packages/token/src/identity.ts`, replace the existing `embedLongForm` doc comment in
`SignTokenOptions`:

```ts
  /**
   * Override the long-form policy for did:peer:4 identities.
   * - true: always use long form (no-op for did:key, where longForm === id).
   * - false: always use short form.
   * - undefined (default): long form on the first token to a given `payload.aud`, short form
   *   thereafter; and always long form when the payload names no single string audience, since
   *   there is then no audience to key first contact on and the recipient may hold no cached
   *   document for this DID.
   */
  embedLongForm?: boolean
```

- [ ] **Step 6: Run the identity tests to verify they pass**

Run: `pnpm --filter @kokuin/token exec vitest run test/identity.test.ts`

Expected: PASS, all tests in the file.

- [ ] **Step 7: Write the failing rotation test**

Append inside `describe('createRotationAssertion', ...)` in `packages/token/test/rotation.test.ts`:

```ts
  it('a peer:4 old identity signs an assertion that verifies with no resolver or cache', async () => {
    const oldId = await createIdentity({
      keys: [
        { purpose: 'sig', alg: 'EdDSA' },
        { purpose: 'kem', alg: 'X25519' },
      ],
    })
    const newId = await createIdentity({ keys: [{ purpose: 'sig', alg: 'EdDSA' }] })
    const assertion = await createRotationAssertion(oldId, newId)
    // A rotation assertion carries no aud, so its iss must be self-resolving.
    expect(assertion.payload.iss).toBe(oldId.longForm)
    await expect(verifyToken(assertion)).resolves.toBeDefined()
  })
```

`createIdentity`, `createRotationAssertion` and `verifyToken` are already imported in this file.

- [ ] **Step 8: Run the rotation tests**

Run: `pnpm --filter @kokuin/token exec vitest run test/rotation.test.ts`

Expected: PASS, 3 tests. It passes on the first run because Step 4 already landed — this test is a
regression guard for a second audience-less producer, not a driver of new source.

- [ ] **Step 9: Run the whole token suite and its type test**

Run: `pnpm --filter @kokuin/token exec vitest run`
Expected: PASS.

Run: `pnpm --filter @kokuin/token exec tsc --noEmit --skipLibCheck -p tsconfig.test.json`
Expected: no output, exit 0.

If any other token test asserts a short-form `iss` on an audience-less peer:4 payload, it encoded
the old behaviour — update it to expect `longForm` and note it in the commit body.

- [ ] **Step 10: Commit**

```bash
git add packages/token/src/identity.ts packages/token/test/identity.test.ts packages/token/test/rotation.test.ts
git commit -m "fix(token): embed the long form in iss for audience-less did:peer:4 tokens

A did:peer:4 signer emitted a short-form iss whenever the payload named no
single string audience. A short form is a hash of the DID document, so a
recipient with no cached document for that DID could not resolve it and
dropped the token at signature verification. The first-contact cache is
keyed on aud, so an audience-less token never consulted it.

pickIss now returns the long form in that case. createRevocationRecord and
createRotationAssertion become verifiable without changing either of them.
embedLongForm: false remains the opt-out for a broadcast path whose
recipients are known to hold the document already."
```

---

### Task 2: Revocation regression test for a `did:peer:4` signer

**Files:**
- Test: `packages/capability/test/revocation.test.ts` (add one test, extend one import)

**Interfaces:**
- Consumes: Task 1's rule — a `did:peer:4` identity's audience-less token carries `longForm` in
  `iss`. `createRevocationRecord(signer: SigningIdentity, jti: string): Promise<RevocationRecord>`
  and `createRevocationChecker(backend: RevocationBackend): VerifyTokenHook` are unchanged.
- Produces: nothing consumed by later tasks.

- [ ] **Step 1: Extend the `@kokuin/token` import**

At the top of `packages/capability/test/revocation.test.ts`, the first line is currently:

```ts
import { randomIdentity, stringifyToken } from '@kokuin/token'
```

Change it to:

```ts
import { createIdentity, randomIdentity, stringifyToken } from '@kokuin/token'
```

- [ ] **Step 2: Write the failing test**

Append inside `describe('revocation', ...)`, after the final
`test('createRevocationRecord produces a signed revocation', ...)`:

```ts
  test('a did:peer:4 signer produces a revocation record a cold verifier can check', async () => {
    // Two keys means chooseMethod picks peer:4 on its own — the shape a KEM key produces.
    const signer = await createIdentity({
      keys: [
        { purpose: 'sig', alg: 'EdDSA' },
        { purpose: 'kem', alg: 'X25519' },
      ],
    })
    const record = await createRevocationRecord(signer, 'cap-peer4')
    // A revocation record carries no aud, so its iss must carry the document with it.
    expect(record.payload.iss).toBe(signer.longForm)

    // A backend that has never seen this signer must still verify and store the record.
    const backend = createMemoryRevocationBackend()
    await backend.add(record)

    const capability = await createCapability(signer, {
      sub: signer.id,
      aud: 'did:key:bob',
      act: '*',
      res: '*',
      jti: 'cap-peer4',
    })
    const checker = createRevocationChecker(backend)
    await expect(checker(capability, stringifyToken(capability))).rejects.toThrow('revoked')

    // The failure mode this replaces, pinned: forcing the old short-form iss makes the same
    // record unverifiable by the same cold backend.
    const shortFormRecord = (await signer.signToken(
      { jti: 'cap-peer4-short', rev: true, iat: Math.floor(Date.now() / 1000) },
      { embedLongForm: false },
    )) as typeof record
    await expect(backend.add(shortFormRecord)).rejects.toThrow(/Unknown DID/)
  })
```

`createCapability`, `createMemoryRevocationBackend`, `createRevocationChecker` and
`createRevocationRecord` are already imported in this file.

The final assertion is what makes this a real regression test rather than a tautology: it drives the
old code path explicitly through `embedLongForm: false` and pins the `Unknown DID` failure, so the
test would still catch a revert of Task 1 by way of its `signer.longForm` assertion above.

- [ ] **Step 3: Run the test with the fix in place**

Run: `pnpm --filter @kokuin/capability exec vitest run test/revocation.test.ts`

Expected: PASS, all tests in the file.

- [ ] **Step 4: Run the whole capability suite and its type test**

Run: `pnpm --filter @kokuin/capability exec vitest run`
Expected: PASS.

Run: `pnpm --filter @kokuin/capability exec tsc --noEmit --skipLibCheck -p tsconfig.test.json`
Expected: no output, exit 0.

- [ ] **Step 5: Commit**

```bash
git add packages/capability/test/revocation.test.ts
git commit -m "test(capability): cover revocation from a did:peer:4 signer

The reported reproduction: a peer:4 grantor's revocation record must verify
against a backend that has never seen the signer. Fails without the
audience-less long-form iss fix in @kokuin/token."
```

---

### Task 3: Verified-token fast path re-binds the payload to the signed bytes

**Files:**
- Modify: `packages/token/src/token.ts:231-235` (the `isVerifiedToken` branch of `verifyTokenInner`)
- Test: `packages/token/test/token.test.ts` (add one describe block)

**Interfaces:**
- Consumes: `getVerifiableData(token: SignedToken<Record<string, unknown>>): string`, already
  defined at `packages/token/src/token.ts:194` — throws
  `Invalid token: data does not match header and payload` when the header or payload no longer
  matches the signed `data`.
- Produces: `verifyToken` on an already-verified object still returns the *same* object reference
  when untouched. Two new rejection messages: `Invalid token: verified token missing data` and the
  existing `Invalid token: data does not match header and payload`.

- [ ] **Step 1: Write the failing tests**

Append to `packages/token/test/token.test.ts`, at the end of the file:

```ts
describe('verified-token re-submission', () => {
  it('rejects a verified token whose payload was mutated in place', async () => {
    const identity = randomIdentity()
    const token = await identity.signToken({ sub: 'alice', role: 'user' })
    const verified = await verifyToken(token)
    expect(isVerifiedToken(verified)).toBe(true)
    // In-process tampering: same object reference, so the WeakSet still admits it.
    ;(verified.payload as Record<string, unknown>).role = 'admin'
    await expect(verifyToken(verified)).rejects.toThrow(
      'Invalid token: data does not match header and payload',
    )
  })

  it('rejects a verified token whose data was removed', async () => {
    const identity = randomIdentity()
    const token = await identity.signToken({ sub: 'alice' })
    const verified = await verifyToken(token)
    ;(verified as unknown as { data: string | undefined }).data = undefined
    await expect(verifyToken(verified)).rejects.toThrow('verified token missing data')
  })

  it('still accepts an untouched verified token and returns the same object', async () => {
    const identity = randomIdentity()
    const token = await identity.signToken({ sub: 'alice' })
    const verified = await verifyToken(token)
    await expect(verifyToken(verified)).resolves.toBe(verified)
  })
})
```

`randomIdentity`, `verifyToken`, `isVerifiedToken` and `describe`/`it`/`expect` are already imported
in this file.

- [ ] **Step 2: Run the tests to verify the first two fail**

Run: `pnpm --filter @kokuin/token exec vitest run test/token.test.ts`

Expected: FAIL on the first two tests — both resolve instead of rejecting, because the fast path
returns the token after checking only time and audience claims. The third test passes already.

- [ ] **Step 3: Add the re-binding check to the fast path**

In `packages/token/src/token.ts`, inside `verifyTokenInner`, replace:

```ts
    if (isVerifiedToken(token)) {
      assertTimeClaimsValid(token.payload as Record<string, unknown>, timeOptions)
      assertAudienceValid(token.payload as Record<string, unknown>, audience)
      return token
    }
```

with:

```ts
    if (isVerifiedToken(token)) {
      // The signature was checked when this object entered `verifiedTokens`, but its payload may
      // have been mutated in place since. Re-bind it to the signed bytes — cheap next to a
      // signature verification, and enough to reject tampering. Without the `data` assertion the
      // check is vacuous: `getVerifiableData` falls back to a freshly recomputed value when `data`
      // is absent, and every object the WeakSet admits carries one.
      if (token.data == null) {
        throw new Error('Invalid token: verified token missing data')
      }
      getVerifiableData(token)
      assertTimeClaimsValid(token.payload as Record<string, unknown>, timeOptions)
      assertAudienceValid(token.payload as Record<string, unknown>, audience)
      return token
    }
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `pnpm --filter @kokuin/token exec vitest run test/token.test.ts`

Expected: PASS, all tests in the file.

- [ ] **Step 5: Run the whole token suite and its type test**

Run: `pnpm --filter @kokuin/token exec vitest run`
Expected: PASS.

Run: `pnpm --filter @kokuin/token exec tsc --noEmit --skipLibCheck -p tsconfig.test.json`
Expected: no output, exit 0.

- [ ] **Step 6: Commit**

```bash
git add packages/token/src/token.ts packages/token/test/token.test.ts
git commit -m "fix(token): re-bind a verified token's payload to its signed bytes

verifyToken's fast path returned early for an object already in the
verifiedTokens WeakSet, re-checking only time and audience claims. Code
holding a genuine verified token could mutate its payload in place and
re-submit the same reference to get the tampered payload back as verified.

The fast path now re-runs getVerifiableData, which compares the header and
payload against the signed bytes. Not remotely reachable — an integrity
gap, not a live vulnerability — and cheaper than a signature re-check."
```

---

### Task 4: O(1) entry-count pre-guard in `assertDocWithinMaxSize`

**Files:**
- Modify: `packages/token/src/peer4.ts:56-60` (constants), `packages/token/src/peer4.ts:67-76` (`assertDocWithinMaxSize`)
- Test: `packages/token/test/peer4.test.ts` (add one describe block, extend one import)

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: `assertDocWithinMaxSize(doc: DIDDoc, maxSize?: number): void` — signature unchanged.
  New rejection message
  `did:peer:4 resolver doc has too many verification methods: <n> > <max>`, thrown *before* the
  existing `did:peer:4 resolver doc too large: <size> > <maxSize>`. Task 5 relies on both.

- [ ] **Step 1: Extend the test file's import**

In `packages/token/test/peer4.test.ts`, the import block is currently:

```ts
import {
  type DIDDoc,
  decodePeer4,
  encodePeer4,
  getPeer4ShortForm,
  isPeer4,
  validateDIDDoc,
} from '../src/peer4.js'
```

Change it to:

```ts
import {
  assertDocWithinMaxSize,
  type DIDDoc,
  decodePeer4,
  encodePeer4,
  getPeer4ShortForm,
  isPeer4,
  validateDIDDoc,
} from '../src/peer4.js'
```

- [ ] **Step 2: Write the failing tests**

Append to `packages/token/test/peer4.test.ts`, at the end of the file:

```ts
describe('assertDocWithinMaxSize', () => {
  const entry = { id: '#key-0', type: 'Multikey', publicKeyMultibase: 'z6MkAbc' }

  function docWithEntries(count: number): DIDDoc {
    return {
      '@context': ['https://www.w3.org/ns/did/v1'],
      verificationMethod: Array.from({ length: count }, (_, i) => ({ ...entry, id: `#key-${i}` })),
    }
  }

  it('accepts a doc under both bounds', () => {
    const doc: DIDDoc = {
      '@context': ['https://www.w3.org/ns/did/v1'],
      verificationMethod: [entry],
      authentication: ['#key-0'],
    }
    expect(() => assertDocWithinMaxSize(doc)).not.toThrow()
  })

  it('rejects on entry count before measuring the serialized doc', () => {
    // 4 KiB default / 40 bytes minimum per entry = 103 entries allowed.
    expect(() => assertDocWithinMaxSize(docWithEntries(104))).toThrow(
      'did:peer:4 resolver doc has too many verification methods: 104 > 103',
    )
  })

  it('scales the entry cap with maxSize', () => {
    // 200 / 40 = 5 entries allowed.
    expect(() => assertDocWithinMaxSize(docWithEntries(6), 200)).toThrow(
      'did:peer:4 resolver doc has too many verification methods: 6 > 5',
    )
  })

  it('still reports the byte-size error for a doc with few but huge entries', () => {
    const doc: DIDDoc = {
      '@context': ['https://www.w3.org/ns/did/v1'],
      verificationMethod: [{ ...entry, publicKeyMultibase: `z${'1'.repeat(8 * 1024)}` }],
    }
    expect(() => assertDocWithinMaxSize(doc)).toThrow(/did:peer:4 resolver doc too large/)
  })
})
```

- [ ] **Step 3: Run the tests to verify two fail**

Run: `pnpm --filter @kokuin/token exec vitest run test/peer4.test.ts`

Expected: FAIL on `rejects on entry count…` and `scales the entry cap…` — both currently throw the
byte-size error rather than the entry-count one. The other two pass already.

- [ ] **Step 4: Add the constant**

In `packages/token/src/peer4.ts`, below the existing `DEFAULT_MAX_DOC_SIZE` declaration and its
neighbours:

```ts
const DEFAULT_MAX_DOC_SIZE = 4 * 1024
// The smallest legal verificationMethod entry — {"id":"","type":"","publicKeyMultibase":""} at 43
// bytes plus an array separator — serializes to 44. Undercounting here only widens the cap, so the
// O(1) guard below can never reject a doc the full byte measure would have accepted.
const MIN_VERIFICATION_METHOD_BYTES = 40
```

- [ ] **Step 5: Add the pre-guard**

In the same file, replace `assertDocWithinMaxSize`:

```ts
/**
 * Throw if a DID document's canonical serialization exceeds `maxSize` bytes.
 * Used to bound a resolver-returned doc before it reaches the O(n^2) base58 encode.
 *
 * The entry-count check runs first and is O(1): `canonicalStringify` below is linear in the
 * document, so an attacker-supplied `verificationMethod` array with millions of entries would
 * otherwise cost linear time before it could be measured and rejected.
 */
export function assertDocWithinMaxSize(doc: DIDDoc, maxSize: number = DEFAULT_MAX_DOC_SIZE): void {
  const maxEntries = Math.ceil(maxSize / MIN_VERIFICATION_METHOD_BYTES)
  if (Array.isArray(doc.verificationMethod) && doc.verificationMethod.length > maxEntries) {
    throw new Error(
      `did:peer:4 resolver doc has too many verification methods: ${doc.verificationMethod.length} > ${maxEntries}`,
    )
  }
  const size = fromUTF(canonicalStringify(doc)).length
  if (size > maxSize) {
    throw new Error(`did:peer:4 resolver doc too large: ${size} > ${maxSize}`)
  }
}
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `pnpm --filter @kokuin/token exec vitest run test/peer4.test.ts`

Expected: PASS, all tests in the file.

- [ ] **Step 7: Run the whole token suite**

Run: `pnpm --filter @kokuin/token exec vitest run`

Expected: PASS. `packages/token/test/did.test.ts` has an existing case whose oversized doc holds a
single huge entry — it stays on the byte-size path and keeps its message.

- [ ] **Step 8: Commit**

```bash
git add packages/token/src/peer4.ts packages/token/test/peer4.test.ts
git commit -m "fix(token): bound peer:4 doc entry count before serializing it

assertDocWithinMaxSize had to canonicalStringify an attacker-supplied
document before it could measure and reject it. That is linear, not the
O(n^2) base58 that was the original bug, but a verificationMethod array
with millions of entries still cost linear time pre-auth.

The entry cap is derived from maxSize and the 44-byte minimum entry, using
40 so that undercounting only widens it — the guard can never reject a
document the full measure would have accepted."
```

---

### Task 5: The DID cache bounds a document before encoding it

**Files:**
- Modify: `packages/token/src/cache.ts:1` (import), `packages/token/src/cache.ts:49-64` (`set`)
- Test: `packages/token/test/cache.test.ts` (add one test)

**Interfaces:**
- Consumes: `assertDocWithinMaxSize(doc: DIDDoc, maxSize?: number): void` from Task 4, and its
  `did:peer:4 resolver doc too large: <size> > <maxSize>` message.
- Produces: `DIDCache.set` may now reject with that message. Signature unchanged:
  `set(shortForm: string, doc: DIDDoc): void | Promise<void>`.

- [ ] **Step 1: Write the failing test**

Append inside `describe('createInMemoryDIDCache', ...)` in `packages/token/test/cache.test.ts`,
after the `is idempotent` test:

```ts
  it('rejects set for an oversized doc before encoding it', async () => {
    const cache = createInMemoryDIDCache()
    const bigDoc = {
      '@context': ['https://www.w3.org/ns/did/v1'],
      verificationMethod: [
        { id: '#key-0', type: 'Multikey', publicKeyMultibase: `z${'1'.repeat(8 * 1024)}` },
      ],
      authentication: ['#key-0'],
    }
    // A matching short form, so the rejection can only come from the size guard.
    const { shortForm } = encodePeer4(bigDoc)
    await expect(cache.set(shortForm, bigDoc)).rejects.toThrow(
      /did:peer:4 resolver doc too large/,
    )
  })
```

`createInMemoryDIDCache` and `encodePeer4` are already imported in this file.

- [ ] **Step 2: Run the test to verify it fails**

Run: `pnpm --filter @kokuin/token exec vitest run test/cache.test.ts`

Expected: FAIL — `set` resolves, because it encodes the document without bounding it first.

- [ ] **Step 3: Add the bound to `set`**

In `packages/token/src/cache.ts`, change the import on line 1:

```ts
import { assertDocWithinMaxSize, type DIDDoc, encodePeer4, isPeer4 } from './peer4.js'
```

and add the guard inside `set`, after the `isPeer4` check and before `encodePeer4`:

```ts
    set(shortForm, doc) {
      if (!isPeer4(shortForm)) {
        return Promise.reject(new Error('DIDCache: short form must be a did:peer:4 identifier'))
      }
      // The doc originated from a resolver. Bound it before the encode below, which is linear in
      // its size — the same guard the resolver path applies.
      try {
        assertDocWithinMaxSize(doc)
      } catch (err) {
        return Promise.reject(err)
      }
      const expected = encodePeer4(doc).shortForm
      if (expected !== shortForm) {
        return Promise.reject(new Error('DIDCache: short form/doc hash mismatch'))
      }
      touch(shortForm, doc)
      while (docs.size > maxEntries) {
        const oldest = docs.keys().next().value
        if (oldest == null) break
        docs.delete(oldest)
      }
      return Promise.resolve()
    },
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `pnpm --filter @kokuin/token exec vitest run test/cache.test.ts`

Expected: PASS, all tests in the file.

- [ ] **Step 5: Run the whole token suite and its type test**

Run: `pnpm --filter @kokuin/token exec vitest run`
Expected: PASS.

Run: `pnpm --filter @kokuin/token exec tsc --noEmit --skipLibCheck -p tsconfig.test.json`
Expected: no output, exit 0.

- [ ] **Step 6: Commit**

```bash
git add packages/token/src/cache.ts packages/token/test/cache.test.ts
git commit -m "fix(token): bound a resolver doc before the DID cache encodes it

createInMemoryDIDCache().set called encodePeer4 with no size bound. It is
reached only after signature verification succeeds, so it was not a pre-auth
DoS, but the document it encodes came from a resolver. It now applies the
same assertDocWithinMaxSize guard as the resolver path."
```

---

### Task 6: Changeset and full-repo verification

**Files:**
- Create: `.changeset/peer4-audienceless-iss.md`

**Interfaces:**
- Consumes: every change from Tasks 1–5.
- Produces: the release note. No code.

- [ ] **Step 1: Write the changeset**

Create `.changeset/peer4-audienceless-iss.md`:

```markdown
---
'@kokuin/token': minor
---

A `did:peer:4` identity now embeds its long form in `iss` whenever the signed payload names no
single string audience.

A short-form `did:peer:4` is a hash of the DID document and cannot be resolved without it, and the
first-contact policy that embeds the long form is keyed on `payload.aud` — so an audience-less token
was unverifiable by any recipient that had not already cached the signer's document. Revocation
records (`@kokuin/capability`) and rotation assertions are both audience-less, so neither bound
anywhere but on the signer's own device.

Pass `embedLongForm: false` to keep the short form on a broadcast path whose recipients are known
to hold the document already.

Also hardened, none of it remotely reachable pre-auth:

- `verifyToken` re-binds an already-verified token's payload to its signed bytes instead of
  trusting object identity alone, so in-process code cannot mutate a verified payload and re-submit
  the same reference.
- `assertDocWithinMaxSize` rejects on `verificationMethod` entry count in O(1) before serializing
  an attacker-supplied document.
- `createInMemoryDIDCache().set` applies that same bound before encoding a resolver-supplied
  document.
```

- [ ] **Step 2: Lint the whole repo**

Run: `pnpm exec biome check --write ./packages ./tests`

Expected: no remaining diagnostics. Review and stage anything it rewrote.

- [ ] **Step 3: Run the full test suite**

Run: `rtk proxy pnpm run test`

Expected: PASS across every package — `turbo run test:types test:unit`.

- [ ] **Step 4: Confirm no other package encoded the old behaviour**

Run: `grep -rn "payload.iss).toBe" packages tests --include="*.ts" | grep -v node_modules | grep -v "/lib/"`

Read each hit. Any assertion of a short-form `iss` on an audience-less `did:peer:4` payload encoded
the old rule and must be updated; a `did:key` assertion is unaffected, since `longForm === id`
there. Fix and re-run Step 3 if anything changes.

- [ ] **Step 5: Commit**

```bash
git add .changeset/peer4-audienceless-iss.md
git commit -m "chore: changeset for the peer:4 audience-less iss fix"
```

- [ ] **Step 6: Update the plan stage**

Set `**Stage:** reviewing` in this file, then:

```bash
git add docs/superpowers/plans/2026-08-03-peer4-audienceless-iss-and-verify-hardening.md
git commit -m "docs: advance plan to reviewing"
```

---

## Notes for the reviewer

- The wire format changes for audience-less `did:peer:4` tokens only. Every `did:key` path is
  untouched, because `longForm === id` there, and `createSigningIdentity` and
  `@kokuin/ledger-device` never call `pickIss` at all.
- `@kokuin/capability` ships no source change. Its revocation fix arrives through `@kokuin/token`.
- The changeset config's `fixed` array is still empty. Making the fixed group release together is
  `next/2026-08-03-release-config-fixed-group-and-license.md`, deliberately out of scope here.
- `backlog/2026-07-02-security-model-docs.md` is unblocked by this branch and should document the
  settled `iss` rule.
