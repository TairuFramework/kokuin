/**
 * Integration tests: Ledger app (via Speculos) + @kokuin/ledger-device.
 *
 * Run with: ./test-speculos.sh (or pnpm run test:speculos)
 *
 * These tests validate the full APDU round-trip between the TypeScript
 * client and the BOLOS C app running in the Speculos emulator.
 *
 * Speculos must be started with seed:
 *   "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
 *
 * The signing and key-agreement flows now gate on an on-device NBGL review.
 * The tests drive that review unattended via a Speculos /automation ruleset
 * (see APPROVE_RULES / REJECT_RULES): rules match the on-screen page titles and
 * advance or confirm with button presses so no manual input is required.
 *
 * Tests auto-skip if Speculos is not available.
 */

import { HDKeyStore } from '@kokuin/deterministic'
import { createTokenEncrypter, decryptToken } from '@kokuin/jwe'
import {
  CLA,
  createLedgerIdentityProvider,
  encodeDerivationPath,
  INS,
  type LedgerTransport,
} from '@kokuin/ledger-device'
import { isFullIdentity, verifyToken } from '@kokuin/token'
import { x25519 } from '@noble/curves/ed25519.js'
import { beforeEach, describe, expect, test } from 'vitest'

const SPECULOS_API_URL = process.env.SPECULOS_URL ?? 'http://127.0.0.1:9999'
const SPECULOS_AVAILABLE = await checkSpeculosAvailable()

const MNEMONIC =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'

const TEST_PATH = "m/44'/876'/0'"

const SW_OK = 0x9000
const SW_USER_REJECTED = 0x6985
const SW_INVALID_DATA = 0x6a80

async function checkSpeculosAvailable(): Promise<boolean> {
  try {
    const response = await fetch(`${SPECULOS_API_URL}/events?currentscreenonly=true`, {
      signal: AbortSignal.timeout(2000),
    })
    return response.ok
  } catch {
    return false
  }
}

// -- NBGL review automation --
//
// A Speculos automation action is a [device-event, button, pressed] tuple.
// Button 1 is the left key, button 2 the right key; a page advance is a
// press-and-release of the right key, a confirm is a simultaneous press of
// both keys. The NBGL review paginates the info screens (title, Account,
// Digest, Peer key) as separate pages that must each be advanced past before
// the confirm ("Sign message" / "Agree key") or reject ("Reject message" /
// "Reject operation") page is reached. The ECDH title wraps onto two lines, so
// the pattern matches its first line ("Review key") rather than the full text.

type AutomationAction = [string, number, boolean]
type AutomationRule = { regexp: string; actions: Array<AutomationAction> }
type AutomationRuleset = { version: number; rules: Array<AutomationRule> }

const ADVANCE: Array<AutomationAction> = [
  ['button', 2, true],
  ['button', 2, false],
]

const CONFIRM: Array<AutomationAction> = [
  ['button', 1, true],
  ['button', 2, true],
  ['button', 1, false],
  ['button', 2, false],
]

const REVIEW_PAGE_PATTERNS = ['Review message', 'Review key', 'Account', 'Digest', 'Peer key']

function advanceRule(pattern: string): AutomationRule {
  return { regexp: pattern, actions: ADVANCE }
}

function confirmRule(pattern: string): AutomationRule {
  return { regexp: pattern, actions: CONFIRM }
}

// Advance through every info page, then press both keys on the confirm page.
const APPROVE_RULES: AutomationRuleset = {
  version: 1,
  rules: [
    ...REVIEW_PAGE_PATTERNS.map(advanceRule),
    confirmRule('Sign message'),
    confirmRule('Agree key'),
  ],
}

// Advance through every info page and past the confirm page, then press both
// keys on the reject page.
const REJECT_RULES: AutomationRuleset = {
  version: 1,
  rules: [
    ...REVIEW_PAGE_PATTERNS.map(advanceRule),
    advanceRule('Sign message'),
    advanceRule('Agree key'),
    confirmRule('Reject message'),
    confirmRule('Reject operation'),
  ],
}

async function setAutomation(ruleset: AutomationRuleset): Promise<void> {
  const response = await fetch(`${SPECULOS_API_URL}/automation`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(ruleset),
  })
  if (!response.ok) {
    throw new Error(`Speculos automation error: ${response.status} ${response.statusText}`)
  }
}

// -- Raw APDU exchange --

function encodeAPDU(cla: number, ins: number, p1: number, p2: number, data?: Uint8Array): string {
  const dataHex = data != null ? Buffer.from(data).toString('hex') : ''
  const lc = data != null ? data.length : 0
  return (
    cla.toString(16).padStart(2, '0') +
    ins.toString(16).padStart(2, '0') +
    p1.toString(16).padStart(2, '0') +
    p2.toString(16).padStart(2, '0') +
    lc.toString(16).padStart(2, '0') +
    dataHex
  )
}

function hexToBytes(hex: string): Uint8Array {
  if (hex.length === 0) return new Uint8Array(0)
  return Uint8Array.from(hex.match(/.{2}/g)?.map((b: string) => Number.parseInt(b, 16)) ?? [])
}

type APDUResponse = { data: Uint8Array; sw: number }

// Posts a raw APDU and returns the response bytes and status word without
// throwing on a non-0x9000 status, so rejection paths can be asserted.
async function exchangeAPDU(apduHex: string): Promise<APDUResponse> {
  const response = await fetch(`${SPECULOS_API_URL}/apdu`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Connection: 'close' },
    body: JSON.stringify({ data: apduHex }),
    keepalive: false,
  })

  if (!response.ok) {
    throw new Error(`Speculos APDU error: ${response.status} ${response.statusText}`)
  }

  const result = (await response.json()) as { data: string }
  const responseHex = result.data
  const sw = Number.parseInt(responseHex.slice(-4), 16)
  return { data: hexToBytes(responseHex.slice(0, -4)), sw }
}

/**
 * Transport that sends APDUs to Speculos via its REST API and throws on any
 * non-0x9000 status word. On-device reviews are approved unattended by the
 * APPROVE_RULES automation installed before each test.
 */
function createSpeculosTransport(): LedgerTransport {
  return {
    async send(
      cla: number,
      ins: number,
      p1: number,
      p2: number,
      data?: Uint8Array,
    ): Promise<Uint8Array> {
      const { data: responseData, sw } = await exchangeAPDU(encodeAPDU(cla, ins, p1, p2, data))
      if (sw !== SW_OK) {
        throw new Error(`APDU error: status word 0x${sw.toString(16)}`)
      }
      return responseData
    },
  }
}

// Install the approve automation before every test so the default flow runs
// unattended; rejection tests override the ruleset within their own body, and
// this restores the approve default for whatever test runs next.
beforeEach(async () => {
  if (!SPECULOS_AVAILABLE) return
  await setAutomation(APPROVE_RULES)
})

// -- Ledger App Tests (raw APDU) --

describe.skipIf(!SPECULOS_AVAILABLE)('Ledger app: APDU protocol', () => {
  test('GET_APP_VERSION returns 3 bytes', async () => {
    const transport = createSpeculosTransport()
    const response = await transport.send(CLA, INS.GET_APP_VERSION, 0x00, 0x00)
    expect(response.length).toBe(3)
    expect(response[0]).toBe(0) // major
    expect(response[1]).toBe(1) // minor
    expect(response[2]).toBe(0) // patch
  })

  test('GET_PUBLIC_KEY returns 32-byte Ed25519 public key', async () => {
    const transport = createSpeculosTransport()
    const pathBytes = encodeDerivationPath(TEST_PATH)
    const response = await transport.send(CLA, INS.GET_PUBLIC_KEY, 0x00, 0x00, pathBytes)
    expect(response.length).toBe(32)
  })

  test('GET_PUBLIC_KEY is deterministic for same path', async () => {
    const transport = createSpeculosTransport()
    const pathBytes = encodeDerivationPath(TEST_PATH)
    const a = await transport.send(CLA, INS.GET_PUBLIC_KEY, 0x00, 0x00, pathBytes)
    const b = await transport.send(CLA, INS.GET_PUBLIC_KEY, 0x00, 0x00, pathBytes)
    expect(a).toEqual(b)
  })

  test('GET_PUBLIC_KEY returns different keys for different paths', async () => {
    const transport = createSpeculosTransport()
    const path0 = encodeDerivationPath(TEST_PATH)
    const path1 = encodeDerivationPath("m/44'/876'/1'")
    const a = await transport.send(CLA, INS.GET_PUBLIC_KEY, 0x00, 0x00, path0)
    const b = await transport.send(CLA, INS.GET_PUBLIC_KEY, 0x00, 0x00, path1)
    expect(a).not.toEqual(b)
  })
})

// -- On-device review: rejection and stale-state guards --

describe.skipIf(!SPECULOS_AVAILABLE)('Ledger app: review rejection and guards', () => {
  test('SIGN_MESSAGE returns 0x6985 when the review is rejected', async () => {
    await setAutomation(REJECT_RULES)

    const pathBytes = encodeDerivationPath(TEST_PATH)
    const message = new TextEncoder().encode('reject-me')
    const data = new Uint8Array(pathBytes.length + message.length)
    data.set(pathBytes)
    data.set(message, pathBytes.length)

    const { data: responseData, sw } = await exchangeAPDU(
      encodeAPDU(CLA, INS.SIGN_MESSAGE, 0x00, 0x00, data),
    )
    expect(sw).toBe(SW_USER_REJECTED)
    expect(responseData.length).toBe(0)
  })

  test('ECDH_X25519 returns 0x6985 when the review is rejected', async () => {
    await setAutomation(REJECT_RULES)

    const pathBytes = encodeDerivationPath(TEST_PATH)
    const ephPub = x25519.getPublicKey(x25519.utils.randomSecretKey())
    const data = new Uint8Array(pathBytes.length + ephPub.length)
    data.set(pathBytes)
    data.set(ephPub, pathBytes.length)

    const { data: responseData, sw } = await exchangeAPDU(
      encodeAPDU(CLA, INS.ECDH_X25519, 0x00, 0x00, data),
    )
    expect(sw).toBe(SW_USER_REJECTED)
    expect(responseData.length).toBe(0)
  })

  test('SIGN_MESSAGE continuation after a completed signature returns 0x6A80', async () => {
    // Complete a full signature so the app clears its pending request state.
    const pathBytes = encodeDerivationPath(TEST_PATH)
    const message = new TextEncoder().encode('done')
    const first = new Uint8Array(pathBytes.length + message.length)
    first.set(pathBytes)
    first.set(message, pathBytes.length)
    const completed = await exchangeAPDU(encodeAPDU(CLA, INS.SIGN_MESSAGE, 0x00, 0x00, first))
    expect(completed.sw).toBe(SW_OK)
    expect(completed.data.length).toBe(64)

    // A stray one-byte continuation (P1=0x80) must fail the request-type guard
    // rather than append to now-cleared state.
    const stale = await exchangeAPDU(
      encodeAPDU(CLA, INS.SIGN_MESSAGE, 0x80, 0x00, new Uint8Array([0x41])),
    )
    expect(stale.sw).toBe(SW_INVALID_DATA)
    expect(stale.data.length).toBe(0)
  })
})

// -- IdentityProvider Integration Tests --

describe.skipIf(!SPECULOS_AVAILABLE)('Ledger app + ledger-identity integration', () => {
  test('provideIdentity() returns FullIdentity with valid DID', async () => {
    const provider = createLedgerIdentityProvider(createSpeculosTransport())
    const identity = await provider.provideIdentity('0')
    expect(identity.id).toMatch(/^did:key:z/)
    expect(isFullIdentity(identity)).toBe(true)
  })

  test('signToken() produces verifiable JWT', async () => {
    const provider = createLedgerIdentityProvider(createSpeculosTransport())
    const identity = await provider.provideIdentity('0')
    const token = await identity.signToken({ data: 'speculos-test' })
    expect(token.payload.iss).toBe(identity.id)
    const verified = await verifyToken(`${token.data}.${token.signature}`)
    expect(verified.payload.data).toBe('speculos-test')
  })

  test('agreeKey() returns 32-byte shared secret', async () => {
    const provider = createLedgerIdentityProvider(createSpeculosTransport())
    const identity = await provider.provideIdentity('0')
    const ephPriv = x25519.utils.randomSecretKey()
    const ephPub = x25519.getPublicKey(ephPriv)
    const shared = await identity.agreeKey(ephPub)
    expect(shared).toBeInstanceOf(Uint8Array)
    expect(shared.length).toBe(32)
  })

  test('decrypt() decrypts JWE encrypted to ledger identity', async () => {
    const provider = createLedgerIdentityProvider(createSpeculosTransport())
    const identity = await provider.provideIdentity('0')
    const encrypter = createTokenEncrypter(identity.id)
    const plaintext = new TextEncoder().encode('secret message')
    const jwe = await encrypter.encrypt(plaintext)
    const decrypted = await decryptToken(identity, jwe)
    expect(decrypted).toEqual(plaintext)
  })
})

// -- Cross-compatibility: Ledger app vs HD keystore --

describe.skipIf(!SPECULOS_AVAILABLE)('Ledger app + hd-keystore cross-compatibility', () => {
  test('same mnemonic produces same DID', async () => {
    const provider = createLedgerIdentityProvider(createSpeculosTransport())
    const ledgerIdentity = await provider.provideIdentity('0')

    const hdStore = HDKeyStore.fromMnemonic(MNEMONIC)
    const hdIdentity = await hdStore.provideIdentity('0')

    expect(ledgerIdentity.id).toBe(hdIdentity.id)
  })

  test('tokens from both sources are verifiable and share same issuer', async () => {
    const provider = createLedgerIdentityProvider(createSpeculosTransport())
    const ledgerIdentity = await provider.provideIdentity('0')

    const hdStore = HDKeyStore.fromMnemonic(MNEMONIC)
    const hdIdentity = await hdStore.provideIdentity('0')

    const ledgerToken = await ledgerIdentity.signToken({ source: 'ledger' })
    const hdToken = await hdIdentity.signToken({ source: 'hd' })

    const ledgerVerified = await verifyToken(`${ledgerToken.data}.${ledgerToken.signature}`)
    const hdVerified = await verifyToken(`${hdToken.data}.${hdToken.signature}`)

    expect(ledgerVerified.payload.iss).toBe(hdVerified.payload.iss)
  })

  test('ECDH produces same shared secret from both sources', async () => {
    const provider = createLedgerIdentityProvider(createSpeculosTransport())
    const ledgerIdentity = await provider.provideIdentity('0')

    const hdStore = HDKeyStore.fromMnemonic(MNEMONIC)
    const hdIdentity = await hdStore.provideIdentity('0')

    const ephPriv = x25519.utils.randomSecretKey()
    const ephPub = x25519.getPublicKey(ephPriv)

    const ledgerShared = await ledgerIdentity.agreeKey(ephPub)
    const hdShared = await hdIdentity.agreeKey(ephPub)

    expect(ledgerShared).toEqual(hdShared)
  })

  test('JWE encrypted by HD identity is decryptable by Ledger identity', async () => {
    const provider = createLedgerIdentityProvider(createSpeculosTransport())
    const ledgerIdentity = await provider.provideIdentity('0')

    const hdStore = HDKeyStore.fromMnemonic(MNEMONIC)
    const hdIdentity = await hdStore.provideIdentity('0')

    // Encrypt with HD identity's DID
    const encrypter = createTokenEncrypter(hdIdentity.id)
    const plaintext = new TextEncoder().encode('cross-compat secret')
    const jwe = await encrypter.encrypt(plaintext)

    // Decrypt with Ledger identity (same underlying key)
    const decrypted = await decryptToken(ledgerIdentity, jwe)
    expect(decrypted).toEqual(plaintext)
  })
})
