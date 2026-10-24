import type { KeyAgreementIdentity } from '@kokuin/token'
import { normalizeDID } from '@kokuin/token'

import { NoAvailableFactor, VaultTampered } from './errors.js'
import type { FactorInput, FactorInputs, SecretFactorKind } from './suite.js'

/** Ordered public descriptors. Unknown kinds are retained for fail-closed suite dispatch. */
export type FactorDescriptor = {
  kind: string
  params: Record<string, unknown>
}

export const SECRET_FACTOR_KINDS: ReadonlyArray<SecretFactorKind> = ['passphrase', 'pin']

export function isSecretFactorKind(kind: string): kind is SecretFactorKind {
  return SECRET_FACTOR_KINDS.includes(kind as SecretFactorKind)
}

export function wrappingNamesExcludedRecipient(
  wrapping: { recipientDID: string | null; factors: ReadonlyArray<FactorDescriptor> },
  excluded: ReadonlySet<string>,
): boolean {
  return [
    wrapping.recipientDID,
    ...wrapping.factors
      .filter((factor) => factor.kind === 'did')
      .map((factor) => factor.params.recipient),
  ].some((recipient) => typeof recipient === 'string' && excluded.has(normalizeDID(recipient)))
}

export function satisfiableFactors(
  descriptors: Array<FactorDescriptor>,
  identity: KeyAgreementIdentity | null,
): Array<SecretFactorKind> | null {
  const needed: Array<SecretFactorKind> = []
  for (const descriptor of descriptors) {
    if (isSecretFactorKind(descriptor.kind)) {
      needed.push(descriptor.kind)
      continue
    }
    if (descriptor.kind !== 'did') return null
    const recipient = descriptor.params.recipient
    if (identity === null || typeof recipient !== 'string') return null
    if (normalizeDID(recipient) !== normalizeDID(identity.id)) return null
  }
  return needed
}

export function factorsFromDescriptors(
  descriptors: Array<FactorDescriptor>,
  inputs?: FactorInputs,
): Array<FactorInput> {
  return descriptors.map((descriptor) => {
    if (descriptor.kind === 'did') {
      const recipient = descriptor.params.recipient
      if (typeof recipient !== 'string')
        throw new VaultTampered('did factor descriptor carries no recipient')
      return { kind: 'did', recipientDID: recipient }
    }
    if (!isSecretFactorKind(descriptor.kind)) throw new NoAvailableFactor(descriptor.kind)
    const input = inputs?.[descriptor.kind]
    if (input == null) throw new NoAvailableFactor(descriptor.kind)
    const { m, t, p } = descriptor.params
    const cost =
      typeof m === 'number' && typeof t === 'number' && typeof p === 'number'
        ? { m, t, p }
        : undefined
    return { kind: descriptor.kind, input, cost }
  })
}

/** Public recipient metadata uses equality form. Descriptors retain resolvable long forms. */
export function recipientDIDForFactors(factors: ReadonlyArray<FactorInput>): string | null {
  const factor = factors[0]
  return factors.length === 1 && factor?.kind === 'did' ? normalizeDID(factor.recipientDID) : null
}
