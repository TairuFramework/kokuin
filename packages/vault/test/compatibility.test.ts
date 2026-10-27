import { createPrivateKey, createPublicKey, diffieHellman } from 'node:crypto'
import { createKeyAgreementIdentityForDID } from '@kokuin/token'
import { gcm } from '@noble/ciphers/aes.js'
import { argon2idAsync } from '@noble/hashes/argon2.js'
import { blake3 } from '@noble/hashes/blake3.js'
import { hkdf } from '@noble/hashes/hkdf.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { canonicalStringify, fromUTF, toB64, toB64U } from '@sozai/codec'
import { createRuntime } from '@sozai/runtime'
import { describe, expect, test } from 'vitest'

import {
  createVaultKeyID,
  descriptorDigest,
  digestParts,
  getSuite,
  VaultSecretRejected,
} from '../src/index.js'

const suite = getSuite(1)
const contentKey = Uint8Array.from({ length: 32 }, (_, i) => i)
const salt = new Uint8Array(16).fill(11)
const iv = new Uint8Array(12).fill(22)
const input = fromUTF('known answer secret')
const cost = { m: 8, t: 1, p: 1 }
const address = { keyID: 'key', keyVersion: 3, wrappingID: 'wrap' }

function fixedRuntime() {
  return createRuntime({
    getRandomValues: (bytes) => {
      const view = new Uint8Array(bytes.buffer, bytes.byteOffset, bytes.byteLength)
      view.set(view.length === 16 ? salt : iv)
      return bytes
    },
  })
}

describe('byte compatibility', () => {
  test('wrap preserves KDF, salt, AAD and ciphertext layout with only the info domain replaced', async () => {
    const secret = await argon2idAsync(input, salt, { ...cost, dkLen: 32 })
    const descriptors = [{ kind: 'passphrase', params: { salt: toB64(salt), ...cost } }]
    const info = fromUTF('kokuin/vault/wrap/v1:1:key:3')
    const kek = hkdf(sha256, secret, fromUTF('wrap'), info, 32)
    const expected = gcm(kek, iv, fromUTF(canonicalStringify(descriptors))).encrypt(contentKey)
    const wrapped = await suite.wrap({
      ...address,
      runtime: fixedRuntime(),
      contentKey,
      factors: [{ kind: 'passphrase', input, cost }],
    })
    expect(wrapped.descriptors).toEqual(descriptors)
    expect(wrapped.iv).toEqual(iv)
    expect(wrapped.wrappedKey).toEqual(expected)
    expect(Buffer.from(wrapped.wrappedKey).toString('hex')).toBe(
      '4e63ac291646b5a9f5b5eac278b14c21554a3cc627717a9a88fcbf545f583a3eae4c939a085f8fde5f9a358fddc3bf14',
    )
    expect(wrapped.wrappedKey).toHaveLength(48)
    expect(
      await suite.unwrap({ ...address, ...wrapped, identity: null, inputs: { passphrase: input } }),
    ).toEqual(contentKey)
  })

  test('did, passphrase and pin secrets concatenate in descriptor order independently of AAD', async () => {
    // PKCS#8 framing lets Node derive X25519 independently of the suite's agreement implementation.
    const privateKey = (bytes: Uint8Array) => {
      return createPrivateKey({
        key: Buffer.concat([Buffer.from('302e020100300506032b656e04220420', 'hex'), bytes]),
        format: 'der',
        type: 'pkcs8',
      })
    }
    const recipientPrivate = new Uint8Array(32).fill(33)
    const recipient = privateKey(recipientPrivate)
    const ephemeral = privateKey(new Uint8Array(32).fill(44))
    const epk = createPublicKey(ephemeral).export({ format: 'der', type: 'spki' }).subarray(-32)
    const recipientDID = 'did:kokuin:zKnownAnswerRecipient'
    const identity = createKeyAgreementIdentityForDID(recipientDID, recipientPrivate)
    const pin = fromUTF('2468')
    const pinSalt = new Uint8Array(16).fill(12)
    const descriptors = [
      { kind: 'did', params: { recipient: recipientDID, epk: toB64(epk) } },
      { kind: 'passphrase', params: { salt: toB64(salt), ...cost } },
      { kind: 'pin', params: { salt: toB64(pinSalt), ...cost } },
    ]
    const secrets = [
      diffieHellman({ privateKey: ephemeral, publicKey: createPublicKey(recipient) }),
      await argon2idAsync(input, salt, { ...cost, dkLen: 32 }),
      await argon2idAsync(pin, pinSalt, { ...cost, dkLen: 32 }),
    ]
    const deriveKEK = (orderedSecrets: Array<Uint8Array>) => {
      return hkdf(
        sha256,
        Buffer.concat(orderedSecrets),
        fromUTF('wrap'),
        fromUTF('kokuin/vault/wrap/v1:1:key:3'),
        32,
      )
    }
    const kek = deriveKEK(secrets)
    expect(Buffer.from(kek).toString('hex')).toBe(
      '4b25b7a5220a6552d3434fea78a6c489e562a789aabe2c7480f36be8d5e175ae',
    )
    const aad = fromUTF(canonicalStringify(descriptors))
    const wrappedKey = gcm(kek, iv, aad).encrypt(contentKey)
    expect(Buffer.from(wrappedKey).toString('hex')).toBe(
      'dffedda7c522e1b090f791d3da6c67ce915e68fced6a0b85c0ba60a2ef24051bf24ccabedc6c768432aa5a299d3eda8c',
    )
    expect(
      await suite.unwrap({
        ...address,
        descriptors,
        iv,
        wrappedKey,
        identity,
        inputs: { passphrase: input, pin },
      }),
    ).toEqual(contentKey)

    // Only secret concatenation changes; the descriptors and AAD stay fixed.
    const reversedKEK = deriveKEK([...secrets].reverse())
    expect(reversedKEK).not.toEqual(kek)
    expect(() => gcm(reversedKEK, iv, aad).decrypt(wrappedKey)).toThrow()
  })

  test('entry preserves the AES-GCM layout with only the AAD domain added', () => {
    const plaintext = fromUTF('known answer bytes')
    const ciphertext = gcm(contentKey, iv, fromUTF('kokuin/vault/entry/v1:1:key:3:entry')).encrypt(
      plaintext,
    )
    const encrypted = suite.encryptEntry({
      ...address,
      runtime: fixedRuntime(),
      contentKey,
      entryID: 'entry',
      plaintext,
    })
    expect(encrypted).toEqual({ iv, ciphertext })
    expect(Buffer.from(encrypted.ciphertext).toString('hex')).toBe(
      '600fe79a639d0703d19cbf2237800e3c8a6c268861ed741542df4664aab029e219b3',
    )
  })

  test('descriptor digest uses the existing canonical JSON and length-framed BLAKE3', () => {
    const descriptors = [{ kind: 'did', params: { recipient: 'did:example:owner', epk: 'AAAA' } }]
    const json = canonicalStringify(descriptors)
    expect(descriptorDigest(descriptors)).toBe(toB64U(blake3(fromUTF(`${json.length}:${json}`))))
    expect(descriptorDigest(descriptors)).toBe(digestParts([json]))
  })

  test('key IDs keep owner-plus-unique BLAKE3 and varint/base36 framing under a generic namespace', () => {
    const unique = new Uint8Array(16).fill(7)
    const owner = 'did:example:owner'
    const digest = blake3(new Uint8Array([...fromUTF(owner), ...unique]))
    const framed = new Uint8Array([0xb6, 0x01, 31, 32, ...digest])
    let value = 0n
    for (const byte of framed) value = value * 256n + BigInt(byte)
    const expected = `k${value.toString(36)}`
    expect(createVaultKeyID(owner, unique)).toBe(expected)
    expect(createVaultKeyID('did:example:other', unique)).not.toBe(expected)
    expect(createVaultKeyID(owner, new Uint8Array(16).fill(8))).not.toBe(expected)
  })

  test.each([false, true])(
    'GCM failure preserves its original cause with trusted digest supplied: %s',
    async (trusted) => {
      const wrapped = await suite.wrap({
        ...address,
        runtime: fixedRuntime(),
        contentKey,
        factors: [{ kind: 'passphrase', input, cost }],
      })
      const corrupted = wrapped.wrappedKey.slice()
      corrupted[0] = (corrupted[0] ?? 0) ^ 1
      const error: unknown = await suite
        .unwrap({
          ...address,
          ...wrapped,
          wrappedKey: corrupted,
          identity: null,
          inputs: { passphrase: input },
          expectedDescriptorDigest: trusted ? wrapped.descriptorDigest : undefined,
        })
        .catch((cause: unknown) => cause)
      expect(error).toBeInstanceOf(VaultSecretRejected)
      if (!(error instanceof VaultSecretRejected)) throw new Error('expected rejection')
      expect(error.cause).toBeInstanceOf(Error)
    },
  )
})
