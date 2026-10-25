import { describe, expect, test } from 'vitest'

import { createPinThrottle } from '../src/pin-throttle.js'

const KEY_ID = 'k-key-1'

function throttleAt(clock: { value: number }) {
  return createPinThrottle({ freeAttempts: 3, baseDelay: 1000, now: () => clock.value })
}

describe('the pin throttle', () => {
  test('the free attempts cost nothing', () => {
    const clock = { value: 1_000_000 }
    const throttle = throttleAt(clock)

    for (let attempt = 0; attempt < 3; attempt++) {
      expect(throttle.retryAfter(KEY_ID)).toBe(0)
      throttle.recordFailure(KEY_ID)
    }
    expect(throttle.attemptsRemaining(KEY_ID)).toBe(0)
  })

  test('the allowance and the delay agree on when it is spent', () => {
    const clock = { value: 1_000_000 }
    const throttle = throttleAt(clock)

    throttle.recordFailure(KEY_ID)
    throttle.recordFailure(KEY_ID)
    expect(throttle.attemptsRemaining(KEY_ID)).toBe(1)
    expect(throttle.retryAfter(KEY_ID)).toBe(0)

    throttle.recordFailure(KEY_ID)
    expect(throttle.attemptsRemaining(KEY_ID)).toBe(0)
    expect(throttle.retryAfter(KEY_ID)).toBeGreaterThan(0)
  })

  test('the delay doubles past the allowance', () => {
    const clock = { value: 1_000_000 }
    const throttle = throttleAt(clock)
    for (let attempt = 0; attempt < 2; attempt++) {
      throttle.recordFailure(KEY_ID)
    }

    for (const expected of [1000, 2000, 4000, 8000]) {
      throttle.recordFailure(KEY_ID)
      expect(throttle.retryAfter(KEY_ID)).toBe(expected)
      clock.value += expected
      expect(throttle.retryAfter(KEY_ID)).toBe(0)
    }
  })

  test('the doubling is capped', () => {
    const clock = { value: 1_000_000 }
    const throttle = createPinThrottle({
      freeAttempts: 0,
      baseDelay: 1000,
      maxDelay: 5000,
      now: () => clock.value,
    })

    for (let attempt = 0; attempt < 20; attempt++) {
      throttle.recordFailure(KEY_ID)
    }

    expect(throttle.retryAfter(KEY_ID)).toBe(5000)
  })

  test('waiting out the delay allows another attempt', () => {
    const clock = { value: 1_000_000 }
    const throttle = throttleAt(clock)
    for (let attempt = 0; attempt < 3; attempt++) {
      throttle.recordFailure(KEY_ID)
    }
    expect(throttle.retryAfter(KEY_ID)).toBe(1000)

    clock.value += 999
    expect(throttle.retryAfter(KEY_ID)).toBe(1)

    clock.value += 1
    expect(throttle.retryAfter(KEY_ID)).toBe(0)
  })

  test('a success clears the count', () => {
    const clock = { value: 1_000_000 }
    const throttle = throttleAt(clock)
    for (let attempt = 0; attempt < 5; attempt++) {
      throttle.recordFailure(KEY_ID)
    }
    expect(throttle.retryAfter(KEY_ID)).toBeGreaterThan(0)

    throttle.recordSuccess(KEY_ID)

    expect(throttle.retryAfter(KEY_ID)).toBe(0)
    expect(throttle.attemptsRemaining(KEY_ID)).toBe(3)
  })

  test('the count is per key', () => {
    const clock = { value: 1_000_000 }
    const throttle = throttleAt(clock)
    for (let attempt = 0; attempt < 5; attempt++) {
      throttle.recordFailure('k-under-attack')
    }

    expect(throttle.retryAfter('k-under-attack')).toBeGreaterThan(0)
    expect(throttle.retryAfter('k-other')).toBe(0)
    expect(throttle.attemptsRemaining('k-other')).toBe(3)
  })

  test('a fresh throttle knows nothing, which is what a restart means', () => {
    const clock = { value: 1_000_000 }
    const first = throttleAt(clock)
    for (let attempt = 0; attempt < 5; attempt++) {
      first.recordFailure(KEY_ID)
    }
    expect(first.retryAfter(KEY_ID)).toBeGreaterThan(0)

    expect(throttleAt(clock).retryAfter(KEY_ID)).toBe(0)
  })
})
