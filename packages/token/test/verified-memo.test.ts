import { ed25519 } from '@noble/curves/ed25519.js'
import { p256 } from '@noble/curves/nist.js'
import { beforeEach, describe, expect, test, vi } from 'vitest'

import { randomIdentity } from '../src/identity.js'
import { verifyToken } from '../src/token.js'
import {
  clearVerifiedSignatureMemo,
  memoizeVerifier,
  VERIFIED_MEMO_MAX_MESSAGE_BYTES,
  VERIFIED_MEMO_SIZE,
  verifiedSignatureMemoSize,
} from '../src/verified-memo.js'
import { getVerifier } from '../src/verifier.js'

// noble's curve objects are frozen, so `vi.spyOn` cannot wrap `verify`: replace them with
// pass-through copies whose `verify` is a spy.
vi.mock('@noble/curves/ed25519.js', async (importOriginal) => {
  const original = await importOriginal<typeof import('@noble/curves/ed25519.js')>()
  return {
    ...original,
    ed25519: {
      ...original.ed25519,
      sign: vi.fn(original.ed25519.sign),
      verify: vi.fn(original.ed25519.verify),
    },
  }
})
vi.mock('@noble/curves/nist.js', async (importOriginal) => {
  const original = await importOriginal<typeof import('@noble/curves/nist.js')>()
  return { ...original, p256: { ...original.p256, verify: vi.fn(original.p256.verify) } }
})

const ed25519Sign = vi.mocked(ed25519.sign)
const ed25519Verify = vi.mocked(ed25519.verify)
// The pass-through implementations the mocks were created with: the real noble functions.
const actual = {
  ed25519: {
    sign: ed25519Sign.getMockImplementation() as typeof ed25519.sign,
    verify: ed25519Verify.getMockImplementation() as typeof ed25519.verify,
  },
}
const p256Verify = vi.mocked(p256.verify)

function signed(message = new TextEncoder().encode('hello')) {
  const privateKey = ed25519.utils.randomSecretKey()
  const publicKey = ed25519.getPublicKey(privateKey)
  const signature = ed25519.sign(message, privateKey)
  return { privateKey, publicKey, signature, message }
}

beforeEach(() => {
  clearVerifiedSignatureMemo()
  ed25519Sign.mockClear()
  ed25519Verify.mockClear()
  p256Verify.mockClear()
})

describe('memoizeVerifier()', () => {
  test('identical inputs verify once, then hit', () => {
    const underlying = vi.fn(() => true)
    const verify = memoizeVerifier('EdDSA', underlying)
    const { publicKey, signature, message } = signed()

    expect(verify(signature, message, publicKey)).toBe(true)
    // Equal bytes, different objects: still a hit.
    expect(verify(signature.slice(), message.slice(), publicKey.slice())).toBe(true)
    expect(underlying).toHaveBeenCalledTimes(1)
  })

  test('a different message under the same signature and key is re-verified and rejected', () => {
    const verify = memoizeVerifier('EdDSA', ed25519.verify)
    const { publicKey, signature, message } = signed()

    expect(verify(signature, message, publicKey)).toBe(true)
    const tampered = message.slice()
    tampered.set([(tampered[0] ?? 0) ^ 1])
    expect(verify(signature, tampered, publicKey)).toBe(false)
    // The rejection did not displace or poison the remembered success.
    expect(verify(signature, message, publicKey)).toBe(true)
  })

  test('a message mutated after it was verified does not hit', () => {
    const underlying = vi.fn(ed25519.verify)
    const verify = memoizeVerifier('EdDSA', underlying)
    const { publicKey, signature, message } = signed()

    expect(verify(signature, message, publicKey)).toBe(true)
    message.set([(message[0] ?? 0) ^ 1])
    expect(verify(signature, message, publicKey)).toBe(false)
    expect(underlying).toHaveBeenCalledTimes(2)
  })

  test('the algorithm is part of the key', () => {
    const underlying = vi.fn(() => true)
    const { publicKey, signature, message } = signed()
    memoizeVerifier('EdDSA', underlying)(signature, message, publicKey)
    memoizeVerifier('ES256', underlying)(signature, message, publicKey)
    expect(underlying).toHaveBeenCalledTimes(2)
  })

  test('key and signature boundaries are part of the key', () => {
    const underlying = vi.fn(() => true)
    const verify = memoizeVerifier('ES256', underlying)
    const message = new Uint8Array([1])
    verify(new Uint8Array([3, 4]), message, new Uint8Array([1, 2]))
    // Same concatenated bytes, split differently.
    verify(new Uint8Array([2, 3, 4]), message, new Uint8Array([1]))
    expect(underlying).toHaveBeenCalledTimes(2)
  })

  test('failures are never cached', () => {
    const underlying = vi.fn(() => false)
    const verify = memoizeVerifier('EdDSA', underlying)
    const { publicKey, signature, message } = signed()

    expect(verify(signature, message, publicKey)).toBe(false)
    expect(verify(signature, message, publicKey)).toBe(false)
    expect(underlying).toHaveBeenCalledTimes(2)
    expect(verifiedSignatureMemoSize()).toBe(0)
  })

  test('thrown errors are never cached', () => {
    const underlying = vi.fn((): boolean => {
      throw new Error('boom')
    })
    const verify = memoizeVerifier('EdDSA', underlying)
    const { publicKey, signature, message } = signed()

    expect(() => verify(signature, message, publicKey)).toThrow('boom')
    expect(() => verify(signature, message, publicKey)).toThrow('boom')
    expect(underlying).toHaveBeenCalledTimes(2)
    expect(verifiedSignatureMemoSize()).toBe(0)
  })

  test('async verifiers: only a resolved true is cached', async () => {
    const underlying = vi.fn(async () => true)
    const verify = memoizeVerifier('EdDSA', underlying)
    const { publicKey, signature, message } = signed()

    await expect(verify(signature, message, publicKey)).resolves.toBe(true)
    expect(await verify(signature, message, publicKey)).toBe(true)
    expect(underlying).toHaveBeenCalledTimes(1)

    const rejecting = vi.fn(async () => {
      throw new Error('nope')
    })
    const failing = memoizeVerifier('ES256', rejecting)
    await expect(failing(signature, message, publicKey)).rejects.toThrow('nope')
    await expect(failing(signature, message, publicKey)).rejects.toThrow('nope')
    expect(rejecting).toHaveBeenCalledTimes(2)
  })

  test('only a strict true is cached', () => {
    const underlying = vi.fn(() => 1 as unknown as boolean)
    const verify = memoizeVerifier('EdDSA', underlying)
    const { publicKey, signature, message } = signed()
    verify(signature, message, publicKey)
    expect(verifiedSignatureMemoSize()).toBe(0)
  })

  test('messages over the size threshold are not cached', () => {
    const underlying = vi.fn(() => true)
    const verify = memoizeVerifier('EdDSA', underlying)
    const { publicKey, signature } = signed()
    const large = new Uint8Array(VERIFIED_MEMO_MAX_MESSAGE_BYTES + 1)

    verify(signature, large, publicKey)
    verify(signature, large, publicKey)
    expect(underlying).toHaveBeenCalledTimes(2)
    expect(verifiedSignatureMemoSize()).toBe(0)

    const atLimit = new Uint8Array(VERIFIED_MEMO_MAX_MESSAGE_BYTES)
    verify(signature, atLimit, publicKey)
    expect(verifiedSignatureMemoSize()).toBe(1)
  })

  test('the memo is bounded and evicts the least recently used entry', () => {
    const underlying = vi.fn(() => true)
    const verify = memoizeVerifier('EdDSA', underlying)
    const publicKey = new Uint8Array(32)
    const message = new Uint8Array([7])
    const sig = (i: number) => {
      const s = new Uint8Array(64)
      new DataView(s.buffer).setUint32(0, i)
      return s
    }

    for (let i = 0; i < VERIFIED_MEMO_SIZE; i++) {
      verify(sig(i), message, publicKey)
    }
    expect(verifiedSignatureMemoSize()).toBe(VERIFIED_MEMO_SIZE)
    // Touch the oldest so it is no longer the least recently used.
    verify(sig(0), message, publicKey)
    expect(underlying).toHaveBeenCalledTimes(VERIFIED_MEMO_SIZE)

    verify(sig(VERIFIED_MEMO_SIZE), message, publicKey)
    expect(verifiedSignatureMemoSize()).toBe(VERIFIED_MEMO_SIZE)

    underlying.mockClear()
    verify(sig(0), message, publicKey) // kept: recently used
    expect(underlying).toHaveBeenCalledTimes(0)
    verify(sig(1), message, publicKey) // evicted
    expect(underlying).toHaveBeenCalledTimes(1)
  })
})

describe('getVerifier()', () => {
  test('default EdDSA verifier is memoized', async () => {
    const verify = getVerifier('EdDSA')
    const { publicKey, signature, message } = signed()
    // A miss yields to the event loop first, so it is asynchronous; a hit answers synchronously.
    await expect(verify(signature, message, publicKey)).resolves.toBe(true)
    expect(verify(signature, message, publicKey)).toBe(true)
    expect(ed25519Verify).toHaveBeenCalledTimes(1)
  })

  test('default ES256 verifier is memoized', async () => {
    const privateKey = p256.utils.randomSecretKey()
    const publicKey = p256.getPublicKey(privateKey)
    const message = new TextEncoder().encode('hello')
    const signature = p256.sign(message, privateKey, { lowS: true })
    const verify = getVerifier('ES256')
    await expect(verify(signature, message, publicKey)).resolves.toBe(true)
    expect(verify(signature, message, publicKey)).toBe(true)
    expect(p256Verify).toHaveBeenCalledTimes(1)
  })

  test('a caller-supplied verifier bypasses the memo', () => {
    const custom = vi.fn(() => true)
    const verify = getVerifier('EdDSA', { EdDSA: custom })
    const { publicKey, signature, message } = signed()
    verify(signature, message, publicKey)
    verify(signature, message, publicKey)
    expect(custom).toHaveBeenCalledTimes(2)
    expect(verifiedSignatureMemoSize()).toBe(0)
  })

  test('a memoized default success does not answer for a caller-supplied verifier', async () => {
    const identity = randomIdentity()
    const token = await identity.signToken({ test: true })
    await verifyToken(token)
    expect(verifiedSignatureMemoSize()).toBe(1)

    const rejecting = vi.fn(() => false)
    await expect(verifyToken(token, { verifiers: { EdDSA: rejecting } })).rejects.toThrow(
      'Invalid signature',
    )
    expect(rejecting).toHaveBeenCalledTimes(1)
  })
})

describe('verifyToken() with the memo', () => {
  test('re-verifying the same serialized token verifies its signature once', async () => {
    const identity = randomIdentity()
    const token = await identity.signToken({ test: true })
    // Fresh objects each time, as a caller re-parsing a stored copy would have.
    const copy = () => JSON.parse(JSON.stringify(token))
    await verifyToken(copy())
    await verifyToken(copy())
    await verifyToken(copy())
    expect(ed25519Verify).toHaveBeenCalledTimes(1)
  })
})

function busy(ms: number): void {
  const end = Date.now() + ms
  while (Date.now() < end) {
    // Stand-in for slow curve math (20-35 ms per operation on a phone).
  }
}

describe('cooperative yields', () => {
  test('a run of verifications lets a timer scheduled before it fire', async () => {
    const identity = randomIdentity()
    const tokens = await Promise.all(
      Array.from({ length: 20 }, (_, i) => identity.signToken({ i })),
    )
    ed25519Verify.mockImplementation((signature, message, publicKey) => {
      busy(2)
      return actual.ed25519.verify(signature, message, publicKey)
    })
    try {
      let done = 0
      let firedAfter = -1
      setTimeout(() => {
        firedAfter = done
      }, 0)
      for (const token of tokens) {
        await verifyToken(JSON.parse(JSON.stringify(token)))
        done++
      }
      expect(ed25519Verify).toHaveBeenCalledTimes(tokens.length)
      expect(firedAfter).toBeGreaterThanOrEqual(0)
      expect(firedAfter).toBeLessThan(tokens.length)
    } finally {
      ed25519Verify.mockImplementation(actual.ed25519.verify)
    }
  })

  test('a run of signatures lets a timer scheduled before it fire', async () => {
    const identity = randomIdentity()
    ed25519Sign.mockImplementation((message, secretKey) => {
      busy(2)
      return actual.ed25519.sign(message, secretKey)
    })
    try {
      const count = 20
      let done = 0
      let firedAfter = -1
      setTimeout(() => {
        firedAfter = done
      }, 0)
      for (let i = 0; i < count; i++) {
        await identity.signToken({ i })
        done++
      }
      expect(ed25519Sign).toHaveBeenCalledTimes(count)
      expect(firedAfter).toBeGreaterThanOrEqual(0)
      expect(firedAfter).toBeLessThan(count)
    } finally {
      ed25519Sign.mockImplementation(actual.ed25519.sign)
    }
  })
})
