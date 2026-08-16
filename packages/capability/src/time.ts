export function now(): number {
  return Math.floor(Date.now() / 1000)
}

/**
 * Default ceiling on a device capability's lifetime.
 *
 * The expiry length *is* the accepted-loss window at an offline verifier: revocation reaches it
 * best-effort, an unrenewed expiry is unconditional. On-log revocation narrows the window but
 * does not remove it, so pick this by how many days of a thief writing as the victim is
 * acceptable — not by renewal convenience.
 */
export const DEFAULT_MAX_DEVICE_LIFETIME_SECONDS = 7 * 24 * 60 * 60

export function assertNonExpired(payload: { exp?: number }, atTime?: number): void {
  if (payload.exp != null && payload.exp < (atTime ?? now())) {
    throw new Error('Invalid token: expired')
  }
}

export function assertValidIssuedAt(payload: { iat?: number }, atTime?: number): void {
  if (payload.iat != null && payload.iat > (atTime ?? now())) {
    throw new Error('Invalid token: issued in the future')
  }
}

/**
 * Reject a token that is not yet valid — the third registered time claim. `verifyToken` enforces it
 * on every token it verifies, so a chain link is covered, but a payload handed straight to
 * `checkCapability` never passes through it and was checked only for `exp` and `iat`.
 */
export function assertValidNotBefore(payload: { nbf?: number }, atTime?: number): void {
  if (payload.nbf != null && payload.nbf > (atTime ?? now())) {
    throw new Error('Invalid token: not yet valid')
  }
}

export type DeviceCapabilityPolicyOptions = {
  maxLifetimeSeconds?: number
  now?: number
}

/**
 * Enforce that a device capability sets a bounded expiry.
 *
 * `exp` is optional in the capability schema and `assertNonExpired` only enforces it when
 * present, so the schema will never require it. Mint and verify paths for device capabilities
 * must call this.
 */
export function assertDeviceCapabilityPolicy(
  payload: { exp?: number },
  options: DeviceCapabilityPolicyOptions = {},
): void {
  const atTime = options.now ?? now()
  const maxLifetime = options.maxLifetimeSeconds ?? DEFAULT_MAX_DEVICE_LIFETIME_SECONDS
  if (payload.exp == null) {
    throw new Error('CapabilityError.PolicyViolation: device capabilities must set exp')
  }
  assertNonExpired(payload, atTime)
  if (payload.exp - atTime > maxLifetime) {
    throw new Error(
      `CapabilityError.PolicyViolation: device capability lifetime exceeds ${maxLifetime}s`,
    )
  }
}
