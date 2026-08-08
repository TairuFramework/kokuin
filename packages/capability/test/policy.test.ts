import { describe, expect, test } from 'vitest'

import {
  assertDeviceCapabilityPolicy,
  DEFAULT_MAX_DELEGATION_DEPTH,
  DEFAULT_MAX_DEVICE_LIFETIME_SECONDS,
} from '../src/index.js'

describe('DEFAULT_MAX_DELEGATION_DEPTH', () => {
  test('is 4 — management, device, connector, plus headroom', () => {
    expect(DEFAULT_MAX_DELEGATION_DEPTH).toBe(4)
  })
})

describe('assertDeviceCapabilityPolicy()', () => {
  const now = 1_800_000_000

  test('rejects a capability with no exp — the schema enforces it only when present', () => {
    expect(() => assertDeviceCapabilityPolicy({}, { now })).toThrow(/must set exp/)
  })

  test('accepts an expiry inside the accepted-loss window', () => {
    expect(() => assertDeviceCapabilityPolicy({ exp: now + 60 * 60 * 24 }, { now })).not.toThrow()
  })

  test('rejects an expiry beyond the default window', () => {
    expect(() => assertDeviceCapabilityPolicy({ exp: now + 60 * 60 * 24 * 30 }, { now })).toThrow(
      /lifetime/,
    )
  })

  test('rejects an already-expired capability', () => {
    expect(() => assertDeviceCapabilityPolicy({ exp: now - 1 }, { now })).toThrow()
  })

  test('honours a caller-supplied window', () => {
    expect(() =>
      assertDeviceCapabilityPolicy(
        { exp: now + 60 * 60 * 24 * 30 },
        { now, maxLifetimeSeconds: 60 * 60 * 24 * 60 },
      ),
    ).not.toThrow()
  })

  test('the default window is seven days', () => {
    expect(DEFAULT_MAX_DEVICE_LIFETIME_SECONDS).toBe(7 * 24 * 60 * 60)
  })
})
