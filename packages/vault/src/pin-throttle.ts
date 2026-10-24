export const DEFAULT_FREE_ATTEMPTS = 3

export const DEFAULT_BASE_DELAY = 1000

export const DEFAULT_MAX_DELAY = 15 * 60 * 1000

export type PinThrottleParams = {
  freeAttempts?: number
  baseDelay?: number
  maxDelay?: number

  now?: () => number
}

export type PinThrottle = {
  retryAfter(keyID: string): number

  attemptsRemaining(keyID: string): number
  recordFailure(keyID: string): void

  recordSuccess(keyID: string): void
}

type Attempts = {
  failures: number
  lastFailureAt: number
}

export function createPinThrottle(params: PinThrottleParams = {}): PinThrottle {
  const freeAttempts = params.freeAttempts ?? DEFAULT_FREE_ATTEMPTS
  const baseDelay = params.baseDelay ?? DEFAULT_BASE_DELAY
  const maxDelay = params.maxDelay ?? DEFAULT_MAX_DELAY
  const now = params.now ?? Date.now
  const attempts = new Map<string, Attempts>()

  function delayAfter(failures: number): number {
    if (failures < freeAttempts) {
      return 0
    }

    return Math.min(baseDelay * 2 ** (failures - freeAttempts), maxDelay)
  }

  return {
    retryAfter(keyID) {
      const record = attempts.get(keyID)
      if (record == null) {
        return 0
      }
      const elapsed = now() - record.lastFailureAt
      return Math.max(0, delayAfter(record.failures) - elapsed)
    },

    attemptsRemaining(keyID) {
      const record = attempts.get(keyID)
      return Math.max(0, freeAttempts - (record?.failures ?? 0))
    },

    recordFailure(keyID) {
      const record = attempts.get(keyID)
      attempts.set(keyID, {
        failures: (record?.failures ?? 0) + 1,
        lastFailureAt: now(),
      })
    },

    recordSuccess(keyID) {
      attempts.delete(keyID)
    },
  }
}
