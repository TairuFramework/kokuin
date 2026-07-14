# Browser — ES256 → non-extractable Ed25519 + X25519

Tasks 9–11. Read `docs/superpowers/specs/2026-07-13-keystore-contract-design.md` §"Why browser is different" and §"Browser key generation" first — the mechanism here is **not** the obvious one, and the obvious one is silently broken.

**The trap.** `subtle.generateKey({ name: 'X25519' }, false, ['deriveBits'])` cannot be used. It mints an *independent* keypair, and a sender never sees that key: `jwe.ts`'s `resolveX25519Key` **derives** the recipient's agreement key from the DID's Ed25519 signing key via `ed25519.utils.toMontgomery`. An independently generated X25519 key is unreachable by any sender, however it is stored — the same structural failure that killed P-256.

**The mechanism.** Generate the seed with noble, derive the montgomery secret, and import **both** keys as non-extractable. The agreement public key is then exactly `toMontgomery(edPub)` — what a sender computes from the DID alone. Verified on Node 26: ECDH agrees with the sender-derived key, WebCrypto's Ed25519 signature verifies under noble, and `exportKey` refuses both keys with `InvalidAccessError`.

The cost, stated plainly: the raw seed is in the JS heap during generation, where `generateKey` would never have exposed it. It is zeroed after import, and IndexedDB only ever holds non-extractable `CryptoKey`s — so XSS after provisioning still cannot exfiltrate. One tick, once per keyID.

---

## Task 9: browser — key material, suite tagging, feature detection

**Files:**
- Modify: `packages/browser/src/utils.ts` (full rewrite)
- Create: `packages/browser/test/utils.test.ts`
- Modify: `packages/browser/package.json` (add `@sozai/codec` — already a dep; confirm `@noble/curves` is too)

**Interfaces:**
- Consumes: nothing.
- Produces, from `./utils.js`:
  - `type BrowserKeyRecord = { suite: 'Ed25519'; signing: CryptoKey; agreement: CryptoKey; publicKey: Uint8Array }`
  - `type LegacyES256Record = CryptoKeyPair` — an **untagged** record, which is all a pre-migration key can be
  - `type StoredKeyRecord = BrowserKeyRecord | LegacyES256Record`
  - `function isLegacyES256Record(record: StoredKeyRecord): record is LegacyES256Record`
  - `function assertEd25519Available(): Promise<void>`
  - `function generateKeyRecord(): Promise<BrowserKeyRecord>`
  - `function getES256PublicKey(keyPair: CryptoKeyPair): Promise<Uint8Array>` — the old `getPublicKey`, renamed and scoped to the legacy path

- [ ] **Step 1: Write the failing test**

Create `packages/browser/test/utils.test.ts`. Node's WebCrypto supports Ed25519/X25519, so these run without a browser.

```ts
import { ed25519, x25519 } from '@noble/curves/ed25519.js'
import { describe, expect, test, vi } from 'vitest'

import {
  assertEd25519Available,
  generateKeyRecord,
  isLegacyES256Record,
} from '../src/utils.js'

describe('generateKeyRecord', () => {
  test('produces non-extractable signing and agreement keys', async () => {
    const record = await generateKeyRecord()
    expect(record.suite).toBe('Ed25519')
    expect(record.signing.extractable).toBe(false)
    expect(record.agreement.extractable).toBe(false)
    expect(record.publicKey).toHaveLength(32)

    await expect(crypto.subtle.exportKey('jwk', record.signing)).rejects.toThrow()
    await expect(crypto.subtle.exportKey('jwk', record.agreement)).rejects.toThrow()
  })

  test('the agreement key is the one a sender derives from the DID — not an independent key', async () => {
    const record = await generateKeyRecord()

    // A sender knows only the Ed25519 public key (from the did:key DID) and derives the
    // agreement key from it. If the agreement key were generated independently, this ECDH
    // would not agree and nothing addressed to the DID could ever be decrypted.
    const senderPrivate = x25519.utils.randomSecretKey()
    const senderPublic = x25519.getPublicKey(senderPrivate)
    const senderShared = x25519.getSharedSecret(
      senderPrivate,
      ed25519.utils.toMontgomery(record.publicKey),
    )

    const senderKey = await crypto.subtle.importKey('raw', senderPublic, { name: 'X25519' }, true, [])
    const ourShared = new Uint8Array(
      await crypto.subtle.deriveBits({ name: 'X25519', public: senderKey }, record.agreement, 256),
    )

    expect(ourShared).toEqual(senderShared)
  })

  test('the signing key produces signatures noble verifies', async () => {
    const record = await generateKeyRecord()
    const message = new TextEncoder().encode('hello')
    const signature = new Uint8Array(
      await crypto.subtle.sign({ name: 'Ed25519' }, record.signing, message),
    )
    expect(ed25519.verify(signature, message, record.publicKey)).toBe(true)
  })

  test('two records are distinct', async () => {
    const first = await generateKeyRecord()
    const second = await generateKeyRecord()
    expect(first.publicKey).not.toEqual(second.publicKey)
  })
})

describe('assertEd25519Available', () => {
  test('resolves where Ed25519 is supported', async () => {
    await expect(assertEd25519Available()).resolves.toBeUndefined()
  })

  test('throws — never falls back — when Ed25519 is unavailable', async () => {
    const generateKey = vi
      .spyOn(crypto.subtle, 'generateKey')
      .mockRejectedValue(new Error('Unrecognized algorithm name'))

    // A silent fallback to P-256 would mint a DIFFERENT DID for the same keyID. That is
    // identity loss, not degradation.
    await expect(assertEd25519Available()).rejects.toThrow(/Ed25519/)
    generateKey.mockRestore()
  })
})

describe('isLegacyES256Record', () => {
  test('an untagged CryptoKeyPair is legacy', async () => {
    const keyPair = (await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['sign'],
    )) as CryptoKeyPair
    expect(isLegacyES256Record(keyPair)).toBe(true)
  })

  test('a suite-tagged record is not legacy', async () => {
    expect(isLegacyES256Record(await generateKeyRecord())).toBe(false)
  })
})
```

- [ ] **Step 2: Run to verify it fails**

Run from `packages/browser`: `pnpm exec vitest run test/utils.test.ts`

Expected: FAIL — none of `generateKeyRecord`, `assertEd25519Available`, `isLegacyES256Record` exist.

- [ ] **Step 3: Rewrite `utils.ts`**

Replace `packages/browser/src/utils.ts`:

```ts
import { ed25519, x25519 } from '@noble/curves/ed25519.js'
import { toB64U } from '@sozai/codec'

/**
 * A key record minted by this version: non-extractable Ed25519 signing key plus the X25519
 * agreement key derived from it, and the Ed25519 public key the DID is built from.
 *
 * `suite` is what distinguishes it from a legacy record. An **untagged** record is ES256 by
 * definition — that is all a pre-migration record can be.
 */
export type BrowserKeyRecord = {
  suite: 'Ed25519'
  signing: CryptoKey
  agreement: CryptoKey
  publicKey: Uint8Array
}

/** A pre-migration record: a bare, untagged P-256 `CryptoKeyPair`. Signing only. */
export type LegacyES256Record = CryptoKeyPair

export type StoredKeyRecord = BrowserKeyRecord | LegacyES256Record

export function isLegacyES256Record(record: StoredKeyRecord): record is LegacyES256Record {
  return (record as BrowserKeyRecord).suite !== 'Ed25519'
}

/**
 * Throw unless WebCrypto can do Ed25519.
 *
 * There is deliberately **no fallback**. Falling back to P-256 would mint a different DID for
 * the same keyID, which is identity loss dressed up as graceful degradation. Requires
 * Chrome 137+, Firefox 130+, or Safari 17+.
 */
export async function assertEd25519Available(): Promise<void> {
  try {
    await globalThis.crypto.subtle.generateKey({ name: 'Ed25519' }, false, ['sign', 'verify'])
  } catch (cause) {
    throw new Error(
      'WebCrypto does not support Ed25519, which @kokuin/browser requires (Chrome 137+, ' +
        'Firefox 130+, Safari 17+). Refusing to fall back to another curve: it would mint a ' +
        'different DID for the same keyID.',
      { cause },
    )
  }
}

/**
 * Mint a new key record.
 *
 * The seed is generated **here**, not by `subtle.generateKey`, and both keys are then imported
 * as non-extractable. This is forced, not stylistic: `jwe.ts` derives a recipient's agreement
 * key from its Ed25519 signing key (`toMontgomery`), so the agreement key MUST be the
 * birational image of the signing key. A `generateKey`'d X25519 keypair is independent, and
 * therefore unreachable by any sender — nothing addressed to the DID could ever be decrypted.
 * Deriving the montgomery secret needs the Ed25519 private scalar, which a non-extractable
 * `generateKey` result never yields.
 *
 * The cost is that the seed exists in the JS heap for the duration of this function. It is
 * zeroed on the way out, and IndexedDB only ever holds the non-extractable `CryptoKey`s — so
 * XSS at any point after provisioning still cannot exfiltrate the key.
 */
export async function generateKeyRecord(): Promise<BrowserKeyRecord> {
  await assertEd25519Available()

  const seed = ed25519.utils.randomSecretKey()
  const publicKey = ed25519.getPublicKey(seed)
  const agreementSecret = ed25519.utils.toMontgomerySecret(seed)
  const agreementPublic = x25519.getPublicKey(agreementSecret)

  try {
    const signing = await globalThis.crypto.subtle.importKey(
      'jwk',
      { kty: 'OKP', crv: 'Ed25519', d: toB64U(seed), x: toB64U(publicKey) },
      { name: 'Ed25519' },
      false,
      ['sign'],
    )
    const agreement = await globalThis.crypto.subtle.importKey(
      'jwk',
      { kty: 'OKP', crv: 'X25519', d: toB64U(agreementSecret), x: toB64U(agreementPublic) },
      { name: 'X25519' },
      false,
      ['deriveBits'],
    )
    return { suite: 'Ed25519', signing, agreement, publicKey }
  } finally {
    seed.fill(0)
    agreementSecret.fill(0)
  }
}

function ecPointCompress(x: Uint8Array, y: Uint8Array): Uint8Array {
  const out = new Uint8Array(x.length + 1)
  out[0] = 2 + (y[y.length - 1] & 1)
  out.set(x, 1)
  return out
}

/** The compressed P-256 public key of a legacy record. Legacy path only. */
export async function getES256PublicKey(keyPair: CryptoKeyPair): Promise<Uint8Array> {
  const rawKey = await globalThis.crypto.subtle.exportKey('raw', keyPair.publicKey)
  return ecPointCompress(new Uint8Array(rawKey.slice(1, 33)), new Uint8Array(rawKey.slice(33, 65)))
}
```

- [ ] **Step 4: Run tests**

Run from `packages/browser`: `pnpm exec vitest run test/utils.test.ts` — expected: PASS (7 tests).

`randomKeyPair` and `getPublicKey` are gone, so `entry.ts`, `identity.ts`, and `index.ts` no longer compile. Tasks 10 and 11 fix them. Do not commit yet — commit at the end of Task 11, when browser is coherent again.

---

## Task 10: browser — identities

Browser cannot statically promise `FullIdentity` from one method, because a legacy record can only sign. Two methods, no conditional types:

```ts
provideIdentity(keyID): Promise<FullIdentity>            // IdentityProvider conformance; throws on a legacy record
provideSigningIdentity(keyID): Promise<SigningIdentity>  // accepts both; a FullIdentity IS a SigningIdentity
```

**Files:**
- Modify: `packages/browser/src/identity.ts` (full rewrite)

**Interfaces:**
- Consumes: `BrowserKeyRecord`, `LegacyES256Record`, `isLegacyES256Record`, `getES256PublicKey` from `./utils.js` (Task 9).
- Produces, from `./identity.js`:
  - `function createBrowserIdentity(record: BrowserKeyRecord): Promise<FullIdentity>`
  - `function createLegacyES256Identity(record: LegacyES256Record): Promise<SigningIdentity>`

  Both are internal to the package — the store methods in Task 11 are the public surface.

- [ ] **Step 1: Write the failing test**

Create `packages/browser/test/identity.test.ts` (replacing the existing one, which tests the ES256-only path):

```ts
import { CODECS, createTokenEncrypter, encryptToken, getDID, verifyToken } from '@kokuin/token'
import { describe, expect, test } from 'vitest'

import { createBrowserIdentity, createLegacyES256Identity } from '../src/identity.js'
import { generateKeyRecord } from '../src/utils.js'

describe('createBrowserIdentity', () => {
  test('yields a did:key EdDSA FullIdentity', async () => {
    const record = await generateKeyRecord()
    const identity = await createBrowserIdentity(record)
    expect(identity.id).toBe(getDID(CODECS.EdDSA, record.publicKey))
    expect(identity.publicKey).toEqual(record.publicKey)
  })

  test('signs tokens the @kokuin/token verifier accepts', async () => {
    const identity = await createBrowserIdentity(await generateKeyRecord())
    const token = await identity.signToken({ aud: 'did:key:zSomeone', sub: 'test' })
    expect(token.header.alg).toBe('EdDSA')
    const verified = await verifyToken(token)
    expect(verified.payload.iss).toBe(identity.id)
  })

  test('decrypts a JWE addressed to its DID — the whole point of the import mechanism', async () => {
    const identity = await createBrowserIdentity(await generateKeyRecord())

    // The sender knows only the DID. If the agreement key were independently generated, this
    // would fail — which is exactly what subtle.generateKey would have produced.
    const jwe = await encryptToken(
      createTokenEncrypter(identity.id),
      new TextEncoder().encode('secret'),
    )
    expect(new TextDecoder().decode(await identity.decrypt(jwe))).toBe('secret')
  })

  test('rejects a payload whose iss is not this identity', async () => {
    const identity = await createBrowserIdentity(await generateKeyRecord())
    await expect(identity.signToken({ iss: 'did:key:zOther' })).rejects.toThrow(
      /issuer does not match/,
    )
  })
})

describe('createLegacyES256Identity', () => {
  async function legacyRecord(): Promise<CryptoKeyPair> {
    return (await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, [
      'sign',
    ])) as CryptoKeyPair
  }

  test('yields a did:key ES256 SigningIdentity — no decrypt', async () => {
    const identity = await createLegacyES256Identity(await legacyRecord())
    expect(identity.id).toMatch(/^did:key:z/)
    expect('decrypt' in identity).toBe(false)
    expect('agreeKey' in identity).toBe(false)
  })

  test('still signs verifiable tokens, with low-S normalization', async () => {
    const identity = await createLegacyES256Identity(await legacyRecord())
    // Repeat: WebCrypto emits high-S about half the time, and the verifier runs lowS: true.
    for (let i = 0; i < 8; i++) {
      const token = await identity.signToken({ sub: `test-${i}` })
      expect(token.header.alg).toBe('ES256')
      await expect(verifyToken(token)).resolves.toBeDefined()
    }
  })
})
```

- [ ] **Step 2: Run to verify it fails**

Run from `packages/browser`: `pnpm exec vitest run test/identity.test.ts` — expected: FAIL, neither function exists.

- [ ] **Step 3: Rewrite `identity.ts`**

Replace `packages/browser/src/identity.ts`:

```ts
import {
  CODECS,
  decryptToken,
  type FullIdentity,
  getDID,
  type SignedHeader,
  type SignedToken,
  type SigningIdentity,
  type SignTokenOptions,
} from '@kokuin/token'
import { p256 } from '@noble/curves/nist.js'
import { b64uFromJSON, fromUTF, toB64U } from '@sozai/codec'

import {
  type BrowserKeyRecord,
  getES256PublicKey,
  type LegacyES256Record,
} from './utils.js'

/**
 * The current identity: non-extractable Ed25519 signing key, plus the X25519 agreement key
 * derived from it. `did:key` EdDSA, so it is addressable by every other kokuin backend and
 * decryptable by anyone who knows only its DID.
 */
export async function createBrowserIdentity(record: BrowserKeyRecord): Promise<FullIdentity> {
  const publicKey = record.publicKey
  const id = getDID(CODECS.EdDSA, publicKey)

  async function signToken<Payload extends Record<string, unknown> = Record<string, unknown>>(
    payload: Payload,
    options: SignTokenOptions = {},
  ): Promise<SignedToken<Payload>> {
    if (payload.iss != null && payload.iss !== id) {
      throw new Error('Invalid payload: issuer does not match signer')
    }

    const fullHeader = {
      ...(options.header ?? {}),
      typ: 'JWT',
      alg: 'EdDSA',
    } as SignedHeader
    const fullPayload = { ...payload, iss: id }
    const data = `${b64uFromJSON(fullHeader)}.${b64uFromJSON(fullPayload)}`

    // Ed25519 signatures are canonical — no low-S normalization needed, unlike ECDSA.
    const signature = await globalThis.crypto.subtle.sign(
      { name: 'Ed25519' },
      record.signing,
      fromUTF(data),
    )

    return { header: fullHeader, payload: fullPayload, signature: toB64U(new Uint8Array(signature)), data }
  }

  async function agreeKey(ephemeralPublicKey: Uint8Array): Promise<Uint8Array> {
    const ephemeral = await globalThis.crypto.subtle.importKey(
      'raw',
      ephemeralPublicKey as BufferSource,
      { name: 'X25519' },
      true,
      [],
    )
    const shared = await globalThis.crypto.subtle.deriveBits(
      { name: 'X25519', public: ephemeral },
      record.agreement,
      256,
    )
    return new Uint8Array(shared)
  }

  async function decrypt(jwe: string): Promise<Uint8Array> {
    return decryptToken({ id, decrypt, agreeKey }, jwe)
  }

  return { id, publicKey, signToken, decrypt, agreeKey }
}

// --- Legacy ES256 path ---
//
// Records minted before the Ed25519 migration. They can only sign: WebCrypto will not let an
// ECDSA key do deriveBits, so they cannot do ECDH, so they cannot decrypt. They keep working,
// and they are NEVER silently re-keyed — that would change the identity's DID under it.

const P256_N = p256.Point.Fn.ORDER

// Web Crypto's subtle.sign does not enforce low-S, so ~half of ECDSA signatures have s > n/2.
// The @kokuin/token verifier runs with `lowS: true` and rejects those for malleability safety.
function normalizeSignatureToLowS(sig: Uint8Array): Uint8Array {
  const parsed = p256.Signature.fromBytes(sig, 'compact')
  if (!parsed.hasHighS()) return sig
  return new p256.Signature(parsed.r, P256_N - parsed.s).toBytes('compact')
}

export async function createLegacyES256Identity(
  record: LegacyES256Record,
): Promise<SigningIdentity> {
  const publicKey = await getES256PublicKey(record)
  const id = getDID(CODECS.ES256, publicKey)

  async function signToken<Payload extends Record<string, unknown> = Record<string, unknown>>(
    payload: Payload,
    options: SignTokenOptions = {},
  ): Promise<SignedToken<Payload>> {
    if (payload.iss != null && payload.iss !== id) {
      throw new Error('Invalid payload: issuer does not match signer')
    }

    const fullHeader = {
      ...(options.header ?? {}),
      typ: 'JWT',
      alg: 'ES256',
    } as SignedHeader
    const fullPayload = { ...payload, iss: id }
    const data = `${b64uFromJSON(fullHeader)}.${b64uFromJSON(fullPayload)}`

    const signature = await globalThis.crypto.subtle.sign(
      { name: 'ECDSA', hash: 'SHA-256' },
      record.privateKey,
      fromUTF(data),
    )

    return {
      header: fullHeader,
      payload: fullPayload,
      signature: toB64U(normalizeSignatureToLowS(new Uint8Array(signature))),
      data,
    }
  }

  return { id, publicKey, signToken }
}
```

- [ ] **Step 4: Run tests**

Run from `packages/browser`: `pnpm exec vitest run test/identity.test.ts` — expected: PASS (6 tests).

`store.ts` and `index.ts` still do not compile. Task 11 closes it out.

---

## Task 11: browser — store, entry, conformance

**Files:**
- Modify: `packages/browser/src/entry.ts` (record type, not `CryptoKeyPair`)
- Modify: `packages/browser/src/store.ts` (`provideIdentity` / `provideSigningIdentity`)
- Modify: `packages/browser/src/index.ts`
- Create: `packages/browser/test/conformance.test.ts`
- Modify: `packages/browser/test/lib.test.ts` (its mock IDB helper stays; the key type changes)

**Interfaces:**
- Consumes: everything from Tasks 9 and 10, plus `mutableKeyStoreConformanceCases` from `@kokuin/token`.
- Produces:
  - `BrowserKeyEntry implements MutableKeyEntry<StoredKeyRecord>`
  - `BrowserKeyStore implements KeyStore<StoredKeyRecord, BrowserKeyEntry>, IdentityProvider<FullIdentity>`
  - `BrowserKeyStore#provideIdentity(keyID): Promise<FullIdentity>` — throws on a legacy record
  - `BrowserKeyStore#provideSigningIdentity(keyID): Promise<SigningIdentity>` — accepts both
  - The free `provideSigningIdentity(keyID, useStore?)` is **removed**.

- [ ] **Step 1: Write the failing test**

Create `packages/browser/test/conformance.test.ts`. Reuse `createMockGetStore` from `lib.test.ts:9-50` — read that file and copy the helper.

```ts
import { mutableKeyStoreConformanceCases } from '@kokuin/token'
import { describe, expect, test } from 'vitest'

import { BrowserKeyEntry, type GetStore } from '../src/entry.js'
import { BrowserKeyStore } from '../src/store.js'
import { generateKeyRecord, type StoredKeyRecord } from '../src/utils.js'

// ... paste createMockGetStore() from lib.test.ts here ...

/** A store wired to a mock IDB, bypassing BrowserKeyStore.open's indexedDB.open. */
function createStore(): BrowserKeyStore {
  return new BrowserKeyStore(createMockGetStore().getStore)
}

function sameRecord(a: StoredKeyRecord, b: StoredKeyRecord): boolean {
  // CryptoKeys are opaque and non-extractable; structured-clone round-trips preserve identity
  // through the mock's Map, so reference equality is the right comparison here.
  return a === b
}

describe('BrowserKeyStore conformance', () => {
  const cases = mutableKeyStoreConformanceCases({
    createStore,
    isSameKey: sameRecord,
    createKey: () => generateKeyRecord(),
  })

  for (const conformanceCase of cases) {
    test(conformanceCase.name, () => conformanceCase.run())
  }
})

describe('BrowserKeyStore identities', () => {
  test('provideIdentity yields a did:key EdDSA FullIdentity', async () => {
    const store = createStore()
    const identity = await store.provideIdentity('user')
    expect(identity.id).toMatch(/^did:key:z/)
    expect(typeof identity.decrypt).toBe('function')
    expect((await store.provideIdentity('user')).id).toBe(identity.id)
  })

  test('provideSigningIdentity returns the same identity for a current record', async () => {
    const store = createStore()
    const full = await store.provideIdentity('user')
    expect((await store.provideSigningIdentity('user')).id).toBe(full.id)
  })
})

describe('legacy ES256 records', () => {
  async function storeWithLegacyKey(keyID: string): Promise<BrowserKeyStore> {
    const mock = createMockGetStore()
    const store = new BrowserKeyStore(mock.getStore)
    const keyPair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, [
      'sign',
    ])
    mock.data.set(keyID, keyPair) // an UNTAGGED record — all a pre-migration key can be
    return store
  }

  test('still sign via provideSigningIdentity', async () => {
    const store = await storeWithLegacyKey('legacy')
    const identity = await store.provideSigningIdentity('legacy')
    const token = await identity.signToken({ sub: 'test' })
    expect(token.header.alg).toBe('ES256')
  })

  test('provideIdentity throws rather than returning something that cannot decrypt', async () => {
    const store = await storeWithLegacyKey('legacy')
    await expect(store.provideIdentity('legacy')).rejects.toThrow(/legacy ES256/)
  })

  test('are never silently re-keyed — the DID stays stable', async () => {
    const store = await storeWithLegacyKey('legacy')
    const first = await store.provideSigningIdentity('legacy')
    await store.provideIdentity('legacy').catch(() => undefined)
    const second = await store.provideSigningIdentity('legacy')
    expect(second.id).toBe(first.id)
  })

  test('a stored suite always wins over the requested one', async () => {
    const store = await storeWithLegacyKey('legacy')
    // provideAsync must NOT mint an Ed25519 record over an existing legacy one.
    const record = await store.entry('legacy').provideAsync()
    expect((record as { suite?: string }).suite).toBeUndefined()
  })
})
```

- [ ] **Step 2: Run to verify it fails**

Run from `packages/browser`: `pnpm exec vitest run test/conformance.test.ts` — expected: FAIL, `BrowserKeyStore` takes an `IDBDatabase` and has no identity methods.

- [ ] **Step 3: Retype the entry**

In `packages/browser/src/entry.ts`: swap `CryptoKeyPair` for `StoredKeyRecord`, `KeyEntry` for `MutableKeyEntry`, and `randomKeyPair` for `generateKeyRecord`. The IDB transaction logic is unchanged — a get-then-put inside **one** transaction is already atomic across tabs, which is why browser needs no `lockPath`.

```ts
import type { MutableKeyEntry } from '@kokuin/token'

import { generateKeyRecord, type StoredKeyRecord } from './utils.js'

export type GetStore = (mode?: IDBTransactionMode) => IDBObjectStore

export class BrowserKeyEntry implements MutableKeyEntry<StoredKeyRecord> {
```

Every `CryptoKeyPair` in the method signatures becomes `StoredKeyRecord`, and in `provideAsync` the generator changes:

```ts
  provideAsync(): Promise<StoredKeyRecord> {
    return generateKeyRecord().then(
      (generated) =>
        new Promise<StoredKeyRecord>((resolve, reject) => {
          const store = this.#getStore('readwrite')
          const getRequest = store.get(this.#keyID)
          let result: StoredKeyRecord = generated
          getRequest.onerror = () => reject(getRequest.error)
          getRequest.onsuccess = () => {
            const existing = getRequest.result as StoredKeyRecord | undefined
            if (existing != null) {
              // A stored record ALWAYS wins over the freshly generated one — including a
              // legacy ES256 record. Overwriting it would change the identity's DID.
              result = existing
            } else {
              store.put(generated, this.#keyID)
            }
          }
          const tx = store.transaction
          tx.oncomplete = () => resolve(result)
          tx.onabort = () => reject(tx.error ?? new Error('Transaction aborted'))
          tx.onerror = () => reject(tx.error ?? new Error('Transaction failed'))
        }),
    )
  }
```

- [ ] **Step 4: Add the identity methods to the store**

In `packages/browser/src/store.ts`: retype the generics, take a `GetStore` in the constructor (so tests can inject a mock — `open` still builds one from the `IDBDatabase`), and add the two identity methods.

```ts
import { createTracer, KokuinAttributeKeys, KokuinSpanNames } from '@kokuin/otel'
import {
  type FullIdentity,
  type IdentityProvider,
  type KeyStore,
  type SigningIdentity,
} from '@kokuin/token'
import { defer } from '@sozai/async'
import { getLogger } from '@sozai/log'
import { withSpan } from '@sozai/otel'

import { BrowserKeyEntry, type GetStore } from './entry.js'
import { createBrowserIdentity, createLegacyES256Identity } from './identity.js'
import { isLegacyES256Record, type StoredKeyRecord } from './utils.js'

const DEFAULT_DB_NAME = 'kokuin:key-store'
const STORE_NAME = 'keys'
const tracer = createTracer('keystore.browser')
const logger = getLogger(['kokuin', 'browser'])

function createGetStore(db: IDBDatabase): GetStore {
  return function getStore(mode: IDBTransactionMode = 'readonly'): IDBObjectStore {
    return db.transaction(STORE_NAME, mode).objectStore(STORE_NAME)
  }
}

export class BrowserKeyStore
  implements KeyStore<StoredKeyRecord, BrowserKeyEntry>, IdentityProvider<FullIdentity>
{
  static #byName: Record<string, Promise<BrowserKeyStore>> = Object.create(null)

  static open(name = DEFAULT_DB_NAME): Promise<BrowserKeyStore> {
    const existing = BrowserKeyStore.#byName[name]
    if (existing != null) {
      return existing
    }

    const { promise, reject, resolve } = defer<BrowserKeyStore>()
    BrowserKeyStore.#byName[name] = promise

    if (typeof globalThis.crypto.subtle === 'undefined') {
      reject(new Error('Unable to open KeyStore: SubtleCrypto is not available'))
      return promise
    }
    if (typeof globalThis.indexedDB === 'undefined') {
      reject(new Error('Unable to open KeyStore: IndexedDB is not available'))
      return promise
    }

    const request = indexedDB.open(name, 1)
    request.onerror = () => reject(request.error)
    request.onsuccess = () => resolve(new BrowserKeyStore(createGetStore(request.result)))
    request.onupgradeneeded = (event) => {
      ;(event.target as IDBOpenDBRequest).result.createObjectStore(STORE_NAME)
    }
    return promise
  }

  #entries: Record<string, BrowserKeyEntry> = Object.create(null)
  #getStore: GetStore

  constructor(getStore: GetStore) {
    this.#getStore = getStore
  }

  entry(keyID: string): BrowserKeyEntry {
    this.#entries[keyID] ??= new BrowserKeyEntry(keyID, this.#getStore)
    return this.#entries[keyID]
  }

  /**
   * The full identity for `keyID` — signing and decryption.
   *
   * **Throws on a legacy ES256 record.** Such a record physically cannot decrypt (WebCrypto
   * will not let an ECDSA key do `deriveBits`), and it is never silently re-keyed, because
   * that would change the identity's DID. Use {@link provideSigningIdentity} to work with one.
   */
  async provideIdentity(keyID: string): Promise<FullIdentity> {
    return withSpan(
      tracer,
      KokuinSpanNames.KEYSTORE_GET_OR_CREATE,
      { attributes: { [KokuinAttributeKeys.KEYSTORE_STORE_TYPE]: 'browser' } },
      async (span) => {
        const record = await this.entry(keyID).provideAsync()
        if (isLegacyES256Record(record)) {
          throw new Error(
            `Key "${keyID}" holds a legacy ES256 record, which cannot decrypt. It is not ` +
              're-keyed automatically: that would change this identity\'s DID. Use ' +
              'provideSigningIdentity() to sign with it, or removeAsync() it first to mint a ' +
              'new Ed25519 identity under a new DID.',
          )
        }
        const identity = await createBrowserIdentity(record)
        span.setAttribute(KokuinAttributeKeys.AUTH_DID, identity.id)
        logger.info('Browser identity resolved: {did}', { did: identity.id })
        return identity
      },
    )
  }

  /**
   * A signing identity for `keyID`, accepting **both** suites.
   *
   * Returns a `FullIdentity` (a subtype of `SigningIdentity`) for a current record, and an
   * ES256 signing identity for a legacy one. New code should prefer {@link provideIdentity},
   * which promises decryption statically.
   */
  async provideSigningIdentity(keyID: string): Promise<SigningIdentity> {
    return withSpan(
      tracer,
      KokuinSpanNames.KEYSTORE_GET_OR_CREATE,
      { attributes: { [KokuinAttributeKeys.KEYSTORE_STORE_TYPE]: 'browser' } },
      async (span) => {
        const record = await this.entry(keyID).provideAsync()
        const identity = isLegacyES256Record(record)
          ? await createLegacyES256Identity(record)
          : await createBrowserIdentity(record)
        span.setAttribute(KokuinAttributeKeys.AUTH_DID, identity.id)
        return identity
      },
    )
  }
}
```

- [ ] **Step 5: Update the index**

`packages/browser/src/index.ts`:

```ts
/**
 * Key store for browser.
 *
 * ## Installation
 *
 * ```sh
 * npm install @kokuin/browser
 * ```
 *
 * @module browser-keystore
 */

export { BrowserKeyEntry, type GetStore } from './entry.js'
export { BrowserKeyStore } from './store.js'
export {
  assertEd25519Available,
  type BrowserKeyRecord,
  generateKeyRecord,
  isLegacyES256Record,
  type LegacyES256Record,
  type StoredKeyRecord,
} from './utils.js'
```

- [ ] **Step 6: Update `lib.test.ts`**

Keep `createMockGetStore`. Replace `randomKeyPair()` with `generateKeyRecord()`, `getPublicKey` with `getES256PublicKey` where it tested the legacy path, and construct stores as `new BrowserKeyStore(getStore)`. Drop the free `provideSigningIdentity` import in favor of the store methods.

- [ ] **Step 7: Run tests, lint, and commit the whole browser change**

Run from `packages/browser`:
- `pnpm exec vitest run` — expected: PASS.
- `pnpm exec tsc --noEmit --skipLibCheck -p tsconfig.test.json` — expected: clean.

From the repo root: `pnpm exec biome check --write ./packages`

Every backend now compiles against the new contract, so this is the **last `--no-verify` commit** — verify the whole repo builds first:

```bash
pnpm run -r build:types   # via: rtk proxy pnpm run -r build:types
```

Expected: all 13 packages pass. If they do, commit normally (no `--no-verify`):

```bash
git add packages/browser
git commit -m "$(cat <<'EOF'
feat(browser)!: non-extractable Ed25519 + X25519, yielding FullIdentity

Browser no longer mints ES256. It now holds a non-extractable Ed25519 signing key
and the X25519 agreement key derived from it, so it yields a FullIdentity with a
did:key EdDSA DID matching node/HD/ledger.

The keys are IMPORTED, not generated: jwe.ts derives a recipient's agreement key
from its Ed25519 signing key, so an independently generated X25519 keypair — what
subtle.generateKey produces — is unreachable by any sender and could never decrypt.
Deriving the montgomery secret needs the private scalar, which a non-extractable
generateKey result never yields. So the seed is generated with noble and both keys
are imported non-extractable.

Legacy ES256 records keep working, signing-only: provideSigningIdentity accepts
them, provideIdentity throws, and they are never silently re-keyed — that would
change the identity's DID.

Ed25519 availability is feature-detected and hard-errors. It never falls back to
P-256: a silent fallback mints a different DID for the same keyID.
EOF
)"
```
