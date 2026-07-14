## Task 2: token — fix the `did:peer:4` KEM gap

Confirmed by `packages/token/test/peer4-kem.test.ts` (already on the branch, 5 passing assertions against the broken behavior): **no sender can encrypt to a peer:4 identity at all**, because `resolveX25519Key` calls the `did:key`-only `getSignatureInfo`. The published `keyAgreement` key is dead weight. Separately, `createIdentity`'s `did:key` path refuses to decrypt.

**Files:**
- Modify: `packages/token/src/did.ts` (add `getAgreementKey`)
- Modify: `packages/token/src/jwe.ts:135-145` (`resolveX25519Key`)
- Modify: `packages/token/src/identity.ts:320-332` (`pickKemKey`) and `:382-390` (`agreeKey` / `decrypt` in `buildIdentity`)
- Modify: `packages/token/src/index.ts` (export `getAgreementKey`)
- Modify: `packages/token/test/peer4-kem.test.ts` (flip from pinning the gap to asserting the fix)

**Interfaces:**
- Consumes: nothing from Task 1.
- Produces: `function getAgreementKey(doc: DIDDoc): Uint8Array | null` from `@kokuin/token`.

- [ ] **Step 1: Rewrite the test to assert the fixed behavior**

Replace `packages/token/test/peer4-kem.test.ts` entirely:

```ts
import { ed25519 } from '@noble/curves/ed25519.js'
import { describe, expect, test } from 'vitest'

import { createIdentity } from '../src/identity.js'
import { createTokenEncrypter, encryptToken } from '../src/jwe.js'
import { isPeer4 } from '../src/peer4.js'

const encoder = new TextEncoder()
const decoder = new TextDecoder()

describe('did:peer:4 keyAgreement', () => {
  async function createPeer4Identity() {
    return await createIdentity({
      keys: [
        { purpose: 'sig', alg: 'EdDSA' },
        { purpose: 'kem', alg: 'X25519' },
      ],
    })
  }

  test('a sig+kem identity is peer:4 and publishes a keyAgreement key', async () => {
    const identity = await createPeer4Identity()
    expect(isPeer4(identity.id)).toBe(true)
    expect(identity.doc.keyAgreement).toEqual(['#key-1'])
  })

  test('encrypting to the long form uses the published keyAgreement key', async () => {
    const identity = await createPeer4Identity()
    const encrypter = createTokenEncrypter(identity.longForm)
    expect(encrypter.recipientID).toBe(identity.id)

    const jwe = await encryptToken(encrypter, encoder.encode('hello'))
    expect(decoder.decode(await identity.decrypt(jwe))).toBe('hello')
  })

  test('the published key is used, NOT the montgomery-derived signing key', async () => {
    const identity = await createPeer4Identity()
    const sig = identity.keys.find((key) => key.purpose === 'sig')
    const kem = identity.keys.find((key) => key.purpose === 'kem')
    if (sig == null || kem == null) throw new Error('expected a sig and a kem key')

    // The two candidate keys are genuinely different, so this test can distinguish them.
    const derived = ed25519.utils.toMontgomery(sig.publicKey)
    expect(derived).not.toEqual(kem.publicKey)

    // A JWE built from the published key decrypts; one built from the derived key does not.
    const good = await encryptToken(createTokenEncrypter(identity.longForm), encoder.encode('ok'))
    expect(decoder.decode(await identity.decrypt(good))).toBe('ok')

    const bad = await encryptToken(
      createTokenEncrypter(derived, { algorithm: 'X25519' }),
      encoder.encode('ok'),
    )
    await expect(identity.decrypt(bad)).rejects.toThrow()
  })

  test('a short form throws — it carries no document to read the key from', async () => {
    const identity = await createPeer4Identity()
    expect(() => createTokenEncrypter(identity.id)).toThrow(/short form/)
  })

  test('a peer:4 identity with no keyAgreement key throws a specific error', async () => {
    const identity = await createIdentity({
      keys: [
        { purpose: 'sig', alg: 'EdDSA' },
        { purpose: 'sig', alg: 'EdDSA' },
      ],
    })
    expect(isPeer4(identity.id)).toBe(true)
    expect(() => createTokenEncrypter(identity.longForm)).toThrow(/no X25519 keyAgreement key/)
  })
})

describe('did:key EdDSA identities are decryptable', () => {
  test('createIdentity did:key can agree and decrypt via the birational map', async () => {
    const identity = await createIdentity({ keys: [{ purpose: 'sig', alg: 'EdDSA' }] })
    expect(isPeer4(identity.id)).toBe(false)

    // A sender knows only the DID, from which it montgomery-derives the agreement key.
    const jwe = await encryptToken(createTokenEncrypter(identity.id), encoder.encode('hello'))
    expect(decoder.decode(await identity.decrypt(jwe))).toBe('hello')
  })
})
```

- [ ] **Step 2: Run to verify it fails**

Run from `packages/token`: `pnpm exec vitest run test/peer4-kem.test.ts`

Expected: FAIL. `encrypting to the long form...` and the `did:key` case both fail with `Invalid DID format`; the short-form and no-keyAgreement cases fail because the thrown message is `Invalid DID format`, not the specific one asserted.

- [ ] **Step 3: Add `getAgreementKey` to `did.ts`**

Append to `packages/token/src/did.ts`. It reuses the file's existing `isCodecMatch` and the `decodeMultibase` import already at line 3.

```ts
/** Multicodec prefix for an X25519 public key, as published in a peer:4 doc. */
const CODEC_X25519_PUB = new Uint8Array([0xec, 0x01])

/**
 * The X25519 public key a DID document publishes for key agreement, or `null` when it
 * publishes none.
 *
 * Unlike a `did:key` EdDSA identity — whose agreement key is *derived* from its signing key
 * via the birational map — a peer:4 identity carries an independent agreement key in its doc.
 * A sender MUST use the published key: the derived one is a different key and will not decrypt.
 */
export function getAgreementKey(doc: DIDDoc): Uint8Array | null {
  const fragments = doc.keyAgreement
  if (fragments == null) {
    return null
  }
  for (const fragment of fragments) {
    const method = doc.verificationMethod.find(
      (verificationMethod: VerificationMethod) => verificationMethod.id === fragment,
    )
    if (method == null) {
      continue
    }
    const bytes = decodeMultibase(method.publicKeyMultibase)
    if (isCodecMatch(CODEC_X25519_PUB, bytes)) {
      return bytes.slice(CODEC_X25519_PUB.length)
    }
  }
  return null
}
```

- [ ] **Step 4: Teach `resolveX25519Key` about peer:4**

In `packages/token/src/jwe.ts`, replace `resolveX25519Key` (lines 135-145). Add `decodePeer4`, `getAgreementKey`, `getPeer4ShortForm`, and `isPeer4` to the existing imports from `./did.js` and `./peer4.js`.

```ts
function resolveX25519Key(recipient: Uint8Array | string): { key: Uint8Array; id?: string } {
  if (typeof recipient !== 'string') {
    return { key: recipient }
  }

  if (isPeer4(recipient)) {
    const shortForm = getPeer4ShortForm(recipient)
    if (recipient === shortForm) {
      // The doc lives in the long form. Resolving a short form needs a DIDResolver, which
      // this sync constructor cannot await — so say so, rather than failing as a bad DID.
      throw new Error(
        `Cannot encrypt to a did:peer:4 short form: ${shortForm}. Pass the long form, which carries the document.`,
      )
    }
    const { doc } = decodePeer4(recipient)
    const key = getAgreementKey(doc)
    if (key == null) {
      throw new Error(`Recipient publishes no X25519 keyAgreement key: ${shortForm}`)
    }
    return { key, id: shortForm }
  }

  const [algorithm, publicKey] = getSignatureInfo(recipient)
  if (algorithm === 'EdDSA') {
    return { key: ed25519.utils.toMontgomery(publicKey), id: recipient }
  }
  throw new Error(`Unsupported DID algorithm for encryption: ${algorithm}`)
}
```

- [ ] **Step 5: Make `did:key` identities decryptable in `createIdentity`**

In `packages/token/src/identity.ts`, replace `pickKemKey` (lines 320-332) with a function that returns the X25519 **private scalar** to agree with, and that falls back to the birational map for a `did:key` identity — mirroring exactly what a sender derives from such a DID.

```ts
/**
 * The X25519 private scalar this identity agrees with, for `kid` or by default.
 *
 * A peer:4 identity uses its published `keyAgreement` key. A `did:key` EdDSA identity has no
 * published agreement key — a sender derives one from its signing key via the birational map —
 * so it must derive the matching secret the same way, exactly as `createDecryptingIdentity` does.
 */
function pickAgreementSecret(
  keys: Array<ResolvedKey>,
  isPeer: boolean,
  kid?: string,
): Uint8Array {
  if (kid != null) {
    const found = keys.find((key) => key.fragment === kid)
    if (found == null) throw new Error(`KidNotFound: ${kid}`)
    if (found.purpose !== 'kem' || found.alg !== 'X25519') {
      throw new Error(`Kid is not a KEM X25519 key: ${kid}`)
    }
    return found.privateKey
  }
  const kem = keys.find((key) => key.purpose === 'kem' && key.alg === 'X25519')
  if (kem != null) {
    return kem.privateKey
  }
  if (!isPeer) {
    const sig = keys.find((key) => key.purpose === 'sig' && key.alg === 'EdDSA')
    if (sig != null) {
      return ed25519.utils.toMontgomerySecret(sig.privateKey)
    }
  }
  throw new Error('No KEM key in identity')
}
```

Then in `buildIdentity`, replace `agreeKey` and `decrypt` (lines 382-390) — `isPeer` is already in scope at line 345:

```ts
  async function agreeKey(ephemeralPublicKey: Uint8Array, kid?: string): Promise<Uint8Array> {
    return x25519.getSharedSecret(pickAgreementSecret(keys, isPeer, kid), ephemeralPublicKey)
  }

  async function decrypt(jwe: string): Promise<Uint8Array> {
    pickAgreementSecret(keys, isPeer) // fail fast when this identity cannot agree at all
    return decryptToken({ id, decrypt, agreeKey }, jwe)
  }
```

- [ ] **Step 6: Export `getAgreementKey`**

In `packages/token/src/index.ts`, add `getAgreementKey` to the existing `./did.js` export block, keeping it alphabetical (it goes after `CODECS`, before `getAlgorithmAndPublicKey`).

- [ ] **Step 7: Run the tests**

Run from `packages/token`:
- `pnpm exec vitest run test/peer4-kem.test.ts` — expected: PASS (6 tests).
- `pnpm exec vitest run` — expected: PASS. Watch `jwe.test.ts`, `token-peer4.test.ts`, and `identity-create.test.ts` in particular: the `did:key` `agreeKey` path changed from throwing to working, so any test asserting `No KEM key in identity` for a **did:key** identity is now asserting the bug and must be updated to expect success. A **peer:4** identity with no kem key still throws that message.
- `pnpm exec tsc --noEmit --skipLibCheck -p tsconfig.test.json` — expected: clean.

- [ ] **Step 8: Commit**

Still `--no-verify` — the backends do not compile until Task 11.

```bash
git add packages/token/src/did.ts packages/token/src/jwe.ts packages/token/src/identity.ts packages/token/src/index.ts packages/token/test/peer4-kem.test.ts
git commit --no-verify -m "$(cat <<'EOF'
fix(token): make did:peer:4 identities encryptable, did:key identities decryptable

resolveX25519Key called the did:key-only getSignatureInfo, so createTokenEncrypter
threw 'Invalid DID format' for every peer:4 recipient — the keyAgreement key
published in the doc was unreachable by any sender. It now reads the published
key from a long form, and throws a specific error for a short form (no doc) or a
doc with no agreement key.

createIdentity's did:key path threw 'No KEM key in identity' from agreeKey, so it
could not decrypt JWEs addressed to its own DID. It now derives the agreement
secret via the birational map, matching createDecryptingIdentity and matching what
a sender derives from the DID.
EOF
)"
```

---

