# deriveSharedSecret Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Export a `deriveSharedSecret(did)` from `@kokuin/token` that performs X25519 key agreement with a recipient DID, without routing through a JWE and without exposing the did:peer:4 vs did:key branch choice to the caller.

**Architecture:** One new public function in `packages/token/src/jwe.ts`. It reuses the existing module-private `resolveX25519Key` for branch selection, then calls a new module-private `agreeWithKey` helper that is extracted from the ephemeral-pair-plus-ECDH lines already inside `encryptWithX25519`. The raw ECDH output is returned unmodified so it is byte-identical to what the recipient's existing `DecryptingIdentity#agreeKey(ephemeralPublicKey)` produces — no new recipient-side API.

**Tech Stack:** TypeScript (ESM, `.js` import specifiers), `@noble/curves` x25519, vitest, biome, changesets, pnpm.

**Spec:** `docs/superpowers/specs/2026-08-07-derive-shared-secret-design.md`

## Global Constraints

- pnpm only. Never `npm` or `yarn`.
- An `rtk` shim intercepts `pnpm run <script>`. Run repo scripts as `rtk proxy pnpm run <script>`, or invoke the tool directly (`pnpm exec vitest run ...`, `pnpm exec biome check ...`). The commands in this plan already follow that rule — use them verbatim.
- All work happens in `packages/token`. Run test commands from `/Users/paul/dev/yulsi/kokuin/packages/token`.
- Relative imports carry a `.js` extension even though the sources are `.ts` (`./did.js`, `../src/jwe.js`). This is the existing convention throughout the package.
- `resolveX25519Key` stays module-private. Only `deriveSharedSecret` and its result type become public.
- The returned `sharedSecret` is the raw X25519 ECDH output — no KDF is applied inside the package.
- Branch: `feat/derive-shared-secret`, already created off `main`. Commit onto it.
- A pre-commit hook runs biome on staged files and `tsc --emitDeclarationOnly` across every workspace package. Commits take ~20s and will reject a type error, so a failing commit means a real problem to fix, not a flake to retry.

## File Structure

| File | Change | Responsibility |
| --- | --- | --- |
| `packages/token/src/jwe.ts` | Modify | Add `SharedSecretResult` type, module-private `agreeWithKey`, public `deriveSharedSecret`. Refactor `encryptWithX25519` onto `agreeWithKey`. |
| `packages/token/src/index.ts` | Modify | Re-export `deriveSharedSecret` (value block) and `SharedSecretResult` (type block) from `./jwe.js`. |
| `packages/token/test/derive-shared-secret.test.ts` | Create | Both round trips, the branch-inversion guard, and the three inherited refusals. |
| `packages/token/test/exports.test.ts` | Modify | Add `deriveSharedSecret` to the public-surface list. |
| `.changeset/derive-shared-secret.md` | Create | Minor bump for `@kokuin/token`. |
| `docs/agents/plans/next/2026-08-07-public-recipient-key-agreement.md` | Move | To `docs/agents/plans/completed/`, per the repo plan lifecycle. |

Three tasks. Task 1 delivers the working function with full test coverage. Task 2 wires the public surface. Task 3 handles release bookkeeping. Each ends with a commit and is independently reviewable.

---

### Task 1: `deriveSharedSecret` in `jwe.ts`

**Files:**
- Modify: `packages/token/src/jwe.ts` (add types and functions; refactor `encryptWithX25519`, currently at lines 86-134)
- Test: `packages/token/test/derive-shared-secret.test.ts` (create)

**Interfaces:**
- Consumes: `resolveX25519Key(recipient: Uint8Array | string): { key: Uint8Array; id?: string }` — module-private in `jwe.ts`, already defined at line 136. `x25519` from `@noble/curves/ed25519.js`, already imported at the top of `jwe.ts`.
- Produces:
  - `type SharedSecretResult = { sharedSecret: Uint8Array; ephemeralPublicKey: Uint8Array }`
  - `function deriveSharedSecret(recipient: string): SharedSecretResult` — synchronous, exported from `jwe.ts`
  - `function agreeWithKey(recipientPublicKey: Uint8Array): SharedSecretResult` — module-private, not exported

**Background the implementer needs:**

A DID resolves to an X25519 public key by one of two rules, and using the wrong one produces a key that encrypts cleanly and silently never decrypts:

- A **did:peer:4** identity publishes an independent agreement key in its DID document. The sender must use the published key.
- A **did:key** EdDSA identity publishes nothing. The sender derives an X25519 key from the Ed25519 signing key via the birational (Montgomery) map.

`resolveX25519Key` already implements both branches and is the single source of that rule. Do not reimplement it, do not export it, and do not inline any part of it — call it.

On the recipient side, `DecryptingIdentity#agreeKey(ephemeralPublicKey)` performs the mirror-image agreement and returns the raw ECDH bytes. That is why `deriveSharedSecret` must return the raw ECDH output too: the two values are supposed to be `toEqual`. Applying a KDF inside would break that mirror.

- [ ] **Step 1: Write the failing tests**

Create `packages/token/test/derive-shared-secret.test.ts`:

```ts
import { ed25519, x25519 } from '@noble/curves/ed25519.js'
import { describe, expect, test } from 'vitest'

import { CODECS, getDID } from '../src/did.js'
import { createIdentity } from '../src/identity.js'
import { deriveSharedSecret } from '../src/jwe.js'
import { isPeer4 } from '../src/peer4.js'

describe('deriveSharedSecret()', () => {
  test('a peer:4 long form agrees with what the recipient derives', async () => {
    const identity = await createIdentity({
      keys: [
        { purpose: 'sig', alg: 'EdDSA' },
        { purpose: 'kem', alg: 'X25519' },
      ],
    })
    expect(isPeer4(identity.id)).toBe(true)

    const { sharedSecret, ephemeralPublicKey } = deriveSharedSecret(identity.longForm)
    expect(sharedSecret).toHaveLength(32)
    expect(ephemeralPublicKey).toHaveLength(32)
    expect(await identity.agreeKey(ephemeralPublicKey)).toEqual(sharedSecret)
  })

  test('a did:key EdDSA identity agrees via the birational map', async () => {
    const identity = await createIdentity({ keys: [{ purpose: 'sig', alg: 'EdDSA' }] })
    expect(isPeer4(identity.id)).toBe(false)

    const { sharedSecret, ephemeralPublicKey } = deriveSharedSecret(identity.id)
    expect(await identity.agreeKey(ephemeralPublicKey)).toEqual(sharedSecret)
  })

  test('a peer:4 uses the published key, NOT the montgomery-derived signing key', async () => {
    const identity = await createIdentity({
      keys: [
        { purpose: 'sig', alg: 'EdDSA' },
        { purpose: 'kem', alg: 'X25519' },
      ],
    })
    const sig = identity.keys.find((key) => key.purpose === 'sig')
    const kem = identity.keys.find((key) => key.purpose === 'kem')
    if (sig == null || kem == null) throw new Error('expected a sig and a kem key')

    // The two candidate keys are genuinely different, so this test can distinguish them.
    expect(ed25519.utils.toMontgomery(sig.publicKey)).not.toEqual(kem.publicKey)
    const derivedSecret = ed25519.utils.toMontgomerySecret(sig.privateKey)

    const { sharedSecret, ephemeralPublicKey } = deriveSharedSecret(identity.longForm)
    // Recomputing against each candidate scalar shows which branch the sender took: only the
    // published KEM key reproduces the secret. This is what fails if the branch rule is ever
    // inverted — the two round-trip tests above would both still pass, because sender and
    // recipient would be wrong in the same direction.
    expect(x25519.getSharedSecret(kem.privateKey, ephemeralPublicKey)).toEqual(sharedSecret)
    expect(x25519.getSharedSecret(derivedSecret, ephemeralPublicKey)).not.toEqual(sharedSecret)
  })

  test('two calls for the same recipient produce different ephemeral keys', async () => {
    const identity = await createIdentity({ keys: [{ purpose: 'sig', alg: 'EdDSA' }] })
    const first = deriveSharedSecret(identity.id)
    const second = deriveSharedSecret(identity.id)
    expect(first.ephemeralPublicKey).not.toEqual(second.ephemeralPublicKey)
    expect(first.sharedSecret).not.toEqual(second.sharedSecret)
  })

  test('a peer:4 short form throws — it carries no document to read the key from', async () => {
    const identity = await createIdentity({
      keys: [
        { purpose: 'sig', alg: 'EdDSA' },
        { purpose: 'kem', alg: 'X25519' },
      ],
    })
    expect(() => deriveSharedSecret(identity.id)).toThrow(/short form/)
  })

  test('a peer:4 with no keyAgreement key throws a specific error', async () => {
    const identity = await createIdentity({
      keys: [
        { purpose: 'sig', alg: 'EdDSA' },
        { purpose: 'sig', alg: 'EdDSA' },
      ],
    })
    expect(isPeer4(identity.id)).toBe(true)
    expect(() => deriveSharedSecret(identity.longForm)).toThrow(/no X25519 keyAgreement key/)
  })

  test('a non-EdDSA did:key throws', () => {
    // ES256 is a supported *signature* codec but has no X25519 agreement path.
    const did = getDID(CODECS.ES256, new Uint8Array(33).fill(1))
    expect(() => deriveSharedSecret(did)).toThrow(/Unsupported DID algorithm for encryption/)
  })
})
```

Notes on the test fixtures, so nothing here is guesswork:

- `createIdentity({ keys: [sig, kem] })` yields a did:peer:4 identity; `createIdentity({ keys: [sig] })` yields a did:key. This is the pattern `test/peer4-kem.test.ts` already uses.
- `identity.longForm` carries the DID document; `identity.id` is the short form for peer:4 and equals `longForm` for did:key. That is why the peer:4 tests pass `longForm` and the did:key tests pass `id`.
- `identity.keys` entries expose `purpose`, `alg`, `publicKey`, and `privateKey` (`ResolvedKey`).
- `getDID` and `CODECS` are `@internal` but genuinely exported from `did.ts`; `test/did.test.ts` builds ES256 DIDs the same way.

- [ ] **Step 2: Run the tests to verify they fail**

```bash
cd /Users/paul/dev/yulsi/kokuin/packages/token && pnpm exec vitest run test/derive-shared-secret.test.ts
```

Expected: every test fails. The import of `deriveSharedSecret` does not resolve, so vitest reports a transform/import error such as `No "deriveSharedSecret" export is defined on the "../src/jwe.js" mock` or `SyntaxError: The requested module '../src/jwe.js' does not provide an export named 'deriveSharedSecret'`.

- [ ] **Step 3: Add the type and the shared ECDH helper**

In `packages/token/src/jwe.ts`, add the type next to the other exported types near the top of the file (after `EncryptOptions`, around line 37):

```ts
export type SharedSecretResult = {
  /**
   * The raw X25519 ECDH output. **Not** uniformly random — run it through a KDF with your own
   * domain separation before using it as a key.
   */
  sharedSecret: Uint8Array
  /**
   * Send this to the recipient. They recover the same `sharedSecret` bytes with
   * `identity.agreeKey(ephemeralPublicKey)`.
   */
  ephemeralPublicKey: Uint8Array
}
```

Then add the module-private helper immediately above `encryptWithX25519`:

```ts
function agreeWithKey(recipientPublicKey: Uint8Array): SharedSecretResult {
  const ephemeralPrivateKey = x25519.utils.randomSecretKey()
  return {
    ephemeralPublicKey: x25519.getPublicKey(ephemeralPrivateKey),
    sharedSecret: x25519.getSharedSecret(ephemeralPrivateKey, recipientPublicKey),
  }
}
```

No low-order-point check is needed here: `@noble/curves` throws `invalid private or public key received` from `scalarMult` when the ECDH result is the identity point.

- [ ] **Step 4: Refactor `encryptWithX25519` onto the helper**

Replace the first three statements of `encryptWithX25519` — the ones currently reading:

```ts
  // Generate ephemeral X25519 key pair
  const ephemeralPrivateKey = x25519.utils.randomSecretKey()
  const ephemeralPublicKey = x25519.getPublicKey(ephemeralPrivateKey)

  // Compute shared secret via ECDH
  const sharedSecret = x25519.getSharedSecret(ephemeralPrivateKey, recipientPublicKey)
```

with:

```ts
  const { sharedSecret, ephemeralPublicKey } = agreeWithKey(recipientPublicKey)
```

Leave the rest of the function untouched — the `concatKDF` call, the IV, the protected header (which reads `ephemeralPublicKey`), and the AES-GCM encryption all keep working against the destructured names.

- [ ] **Step 5: Add `deriveSharedSecret`**

Add it directly after `resolveX25519Key`, before `createTokenEncrypter`, so the branch rule and its two consumers stay adjacent:

```ts
/**
 * Perform X25519 key agreement with a recipient DID, without building a JWE.
 *
 * Resolves the recipient's agreement key by the same rule `createTokenEncrypter` uses — a
 * did:peer:4 identity's published `keyAgreement` key, or an EdDSA `did:key`'s birationally
 * derived one — generates a single-use ephemeral key pair, and returns the ECDH output.
 * The ephemeral private key never leaves this function.
 *
 * The recipient recovers the identical bytes with `identity.agreeKey(ephemeralPublicKey)`.
 *
 * ```ts
 * const { sharedSecret, ephemeralPublicKey } = deriveSharedSecret(recipientDID)
 * // ship ephemeralPublicKey alongside whatever the secret protects
 * ```
 *
 * The result is a raw ECDH output, not a key: run it through a KDF before use.
 *
 * @param recipient a `did:key` EdDSA DID, or a `did:peer:4` **long form**. A peer:4 short form
 *   throws — the document that carries the agreement key lives only in the long form.
 */
export function deriveSharedSecret(recipient: string): SharedSecretResult {
  return agreeWithKey(resolveX25519Key(recipient).key)
}
```

- [ ] **Step 6: Run the new tests**

```bash
cd /Users/paul/dev/yulsi/kokuin/packages/token && pnpm exec vitest run test/derive-shared-secret.test.ts
```

Expected: PASS, 7 tests.

- [ ] **Step 7: Run the whole package suite to prove the refactor was behaviour-preserving**

```bash
cd /Users/paul/dev/yulsi/kokuin/packages/token && pnpm exec vitest run
```

Expected: PASS. `test/jwe.test.ts`, `test/peer4-kem.test.ts`, and `test/envelope.test.ts` all exercise `encryptWithX25519` through the JWE path; any of them failing means Step 4 changed behaviour.

- [ ] **Step 8: Lint and typecheck**

```bash
cd /Users/paul/dev/yulsi/kokuin/packages/token && pnpm exec biome check --write src test && pnpm exec tsc --noEmit --skipLibCheck -p tsconfig.test.json
```

Expected: biome reports no remaining diagnostics, tsc prints nothing.

- [ ] **Step 9: Commit**

```bash
cd /Users/paul/dev/yulsi/kokuin && git add packages/token/src/jwe.ts packages/token/test/derive-shared-secret.test.ts && git commit -m "feat(token): add deriveSharedSecret for recipient key agreement

Key agreement with a recipient DID without building a JWE. Reuses the
module-private resolveX25519Key so the peer:4 vs did:key branch rule
stays in one place, and returns the raw ECDH output so the recipient's
existing agreeKey() is an exact mirror.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 2: Public surface

**Files:**
- Modify: `packages/token/src/index.ts` (the two `./jwe.js` blocks, lines 55-72)
- Test: `packages/token/test/exports.test.ts`

**Interfaces:**
- Consumes: `deriveSharedSecret` and `SharedSecretResult` from Task 1.
- Produces: both names importable from `@kokuin/token` / `../src/index.js`.

`index.ts` keeps types and values in separate export blocks, each alphabetised. `SharedSecretResult` goes in the `export type { ... } from './jwe.js'` block; `deriveSharedSecret` goes in the `export { ... } from './jwe.js'` block.

- [ ] **Step 1: Write the failing test**

In `packages/token/test/exports.test.ts`, add `'deriveSharedSecret'` to the `it.each([...])` list — put it after `'createIdentity'`:

```ts
    'createIdentity',
    'deriveSharedSecret',
    'createRotationAssertion',
```

- [ ] **Step 2: Run it to verify it fails**

```bash
cd /Users/paul/dev/yulsi/kokuin/packages/token && pnpm exec vitest run test/exports.test.ts
```

Expected: FAIL — `exports deriveSharedSecret` reports `expected undefined to be defined`.

- [ ] **Step 3: Add the exports**

In `packages/token/src/index.ts`, extend the type block:

```ts
export type {
  ConcatKDFParams,
  EncryptOptions,
  EnvelopeMode,
  JWEHeader,
  SharedSecretResult,
  TokenEncrypter,
  UnwrapOptions,
  UnwrappedEnvelope,
  WrapOptions,
} from './jwe.js'
```

and the value block:

```ts
export {
  concatKDF,
  createTokenEncrypter,
  decryptToken,
  deriveSharedSecret,
  encryptToken,
  unwrapEnvelope,
  wrapEnvelope,
} from './jwe.js'
```

- [ ] **Step 4: Run the tests**

```bash
cd /Users/paul/dev/yulsi/kokuin/packages/token && pnpm exec vitest run && pnpm exec tsc --noEmit --skipLibCheck -p tsconfig.test.json
```

Expected: PASS, and tsc silent.

- [ ] **Step 5: Commit**

```bash
cd /Users/paul/dev/yulsi/kokuin && git add packages/token/src/index.ts packages/token/test/exports.test.ts && git commit -m "feat(token): export deriveSharedSecret and SharedSecretResult

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 3: Changeset and plan lifecycle

**Files:**
- Create: `.changeset/derive-shared-secret.md`
- Move: `docs/agents/plans/next/2026-08-07-public-recipient-key-agreement.md` → `docs/agents/plans/completed/`

**Interfaces:**
- Consumes: the shipped API from Tasks 1 and 2. Nothing consumes this task.

`@kokuin/token` is in the fixed release group (token, capability, browser, node, deterministic release together), so naming `@kokuin/token: minor` is sufficient — changesets bumps the rest.

- [ ] **Step 1: Write the changeset**

Create `.changeset/derive-shared-secret.md` with exactly this content (the inner triple-backtick block is part of the changeset body — keep it):

````markdown
---
'@kokuin/token': minor
---

New `deriveSharedSecret(did)` performs X25519 key agreement with a recipient DID directly, without
building a JWE to carry a secret that the recipient could have derived.

Resolving a recipient DID to the key you encrypt to has two branches — a `did:peer:4` identity
publishes an independent `keyAgreement` key that the sender MUST use, while an EdDSA `did:key`
publishes none and the sender derives one from the signing key via the birational map. Picking the
wrong branch produces a key that encrypts cleanly and silently never decrypts. Until now that rule
lived in a module-private function reachable only through `createTokenEncrypter`, so a consumer
wanting a plain ECDH secret had to either reimplement it or ship a random secret inside a JWE it
did not otherwise need.

`deriveSharedSecret` generates the ephemeral key pair internally and returns
`{ sharedSecret, ephemeralPublicKey }`. The ephemeral private key never leaves the function and
the caller never holds the resolved recipient key, so neither the branch choice nor ephemeral key
hygiene can be got wrong from outside. The recipient recovers the identical bytes with the existing
`identity.agreeKey(ephemeralPublicKey)`.

```ts
const { sharedSecret, ephemeralPublicKey } = deriveSharedSecret(recipientDID)
// recipient, unchanged API:
const sharedSecret = await identity.agreeKey(ephemeralPublicKey)
```

`sharedSecret` is the raw ECDH output, not a key — it is not uniformly random, so run it through a
KDF with your own domain separation before use. It is returned raw precisely so that it mirrors
`agreeKey` byte for byte.

Errors are inherited unchanged from the resolution `createTokenEncrypter` already performs: a
`did:peer:4` short form is refused (the document lives in the long form), as is a long form
publishing no usable X25519 `keyAgreement` entry, as is any non-EdDSA `did:key`.
````

- [ ] **Step 2: Move the origin plan to completed**

```bash
cd /Users/paul/dev/yulsi/kokuin && git mv docs/agents/plans/next/2026-08-07-public-recipient-key-agreement.md docs/agents/plans/completed/
```

- [ ] **Step 3: Verify the full repo is green before committing**

```bash
cd /Users/paul/dev/yulsi/kokuin && rtk proxy pnpm run -r test
```

Expected: PASS across every workspace package. The `rtk proxy` prefix is required here — see Global Constraints.

- [ ] **Step 4: Commit**

```bash
cd /Users/paul/dev/yulsi/kokuin && git add .changeset/derive-shared-secret.md docs/agents/plans && git commit -m "chore: changeset for deriveSharedSecret, close origin plan

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

## Done when

- `deriveSharedSecret` is importable from `@kokuin/token` and its output round-trips through `identity.agreeKey` for both a did:peer:4 and a did:key recipient.
- The branch-inversion guard test passes, and `jwe.ts` contains exactly one X25519 ECDH implementation.
- `rtk proxy pnpm run -r test` is green, a changeset is staged, and the origin plan sits in `completed/`.

Not in scope, per the spec: `getAgreementKey` (already public and correct), `pickAgreementSecret` on the recipient side, an async variant that resolves a peer:4 short form through a `DIDResolver`, and kubun's swap from its JWE-wrapped random secret to this API — that last one is a kubun change, tracked there.
