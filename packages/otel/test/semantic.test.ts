import { describe, expect, test } from 'vitest'

import { createTracer, KokuinAttributeKeys, KokuinSpanNames } from '../src/index.js'

describe('KokuinSpanNames', () => {
  test('token + keystore span names are kokuin-prefixed', () => {
    expect(KokuinSpanNames.TOKEN_SIGN).toBe('kokuin.token.sign')
    expect(KokuinSpanNames.TOKEN_VERIFY).toBe('kokuin.token.verify')
    expect(KokuinSpanNames.KEYSTORE_GET_OR_CREATE).toBe('kokuin.keystore.get_or_create')
  })
})

describe('KokuinAttributeKeys', () => {
  test('auth + keystore attrs are kokuin-prefixed', () => {
    expect(KokuinAttributeKeys.AUTH_DID).toBe('kokuin.auth.did')
    expect(KokuinAttributeKeys.AUTH_ALGORITHM).toBe('kokuin.auth.algorithm')
    expect(KokuinAttributeKeys.KEYSTORE_KEY_CREATED).toBe('kokuin.keystore.key_created')
    expect(KokuinAttributeKeys.KEYSTORE_STORE_TYPE).toBe('kokuin.keystore.store_type')
  })
})

describe('createTracer', () => {
  test('returns a Tracer', () => {
    const tracer = createTracer('token')
    expect(typeof tracer.startSpan).toBe('function')
  })
})
