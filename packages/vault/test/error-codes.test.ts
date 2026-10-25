import { describe, expect, test } from 'vitest'

import * as errors from '../src/errors.js'

const constructors: Record<string, () => errors.VaultError> = {
  VaultError: () => new errors.VaultError('generic', { code: 'VAULT_ERROR' }),
  VaultPinRejected: () =>
    new errors.VaultPinRejected('key', { attemptsRemaining: 2, retryAfter: 0 }),
  VaultSecretRejected: () => new errors.VaultSecretRejected(['passphrase']),
  VaultTampered: () => new errors.VaultTampered('descriptors altered'),
  InvalidVaultFactors: () => new errors.InvalidVaultFactors('duplicate pin factor'),
  NoAvailableFactor: () => new errors.NoAvailableFactor('did'),
  UnsupportedVaultSuite: () => new errors.UnsupportedVaultSuite(99),
}

function exportedErrorClasses(): Array<string> {
  return Object.entries(errors)
    .filter(([, value]) => typeof value === 'function' && value.prototype instanceof Error)
    .map(([name]) => name)
    .sort()
}

describe('vault error codes', () => {
  test('every exported error class is covered here', () => {
    expect(exportedErrorClasses()).toEqual(Object.keys(constructors).sort())
  })

  test('every error carries a distinct code', () => {
    const codes = Object.values(constructors).map((build) => build().code)
    expect(new Set(codes).size).toBe(codes.length)
  })

  test('a subclass does not inherit its parent code', () => {
    const pin = new errors.VaultPinRejected('key', { attemptsRemaining: 2, retryAfter: 0 })
    expect(pin).toBeInstanceOf(errors.VaultSecretRejected)
    expect(pin.code).toBe('VAULT_PIN_REJECTED')
    expect(new errors.VaultSecretRejected(['passphrase']).code).toBe('VAULT_SECRET_REJECTED')
  })

  test('the code survives serialisation that loses the class', () => {
    const caught: unknown = new errors.NoAvailableFactor('did')
    const code = caught instanceof errors.VaultError ? caught.code : null
    expect(JSON.parse(JSON.stringify({ code }))).toEqual({ code: 'VAULT_FACTOR_UNAVAILABLE' })
  })
})
