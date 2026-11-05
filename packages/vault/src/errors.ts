export type VaultErrorParams = { message: string; options: VaultErrorOptions }
export type NoAvailableFactorParams = { kind: string }
export type InvalidVaultFactorsParams = { reason: string }
export type UnsupportedVaultSuiteParams = { suite: number }
export type VaultTamperedParams = { message: string; options?: ErrorOptions }
export type VaultSecretRejectedParams = {
  kinds: Array<string>
  options?: ErrorOptions & { keyID?: string; code?: VaultErrorCode }
}
export type VaultPinRejectedParams = {
  keyID: string
  options: ErrorOptions & { attemptsRemaining: number; retryAfter: number }
}
export type VaultErrorCode =
  | 'VAULT_ERROR'
  | 'VAULT_FACTOR_UNAVAILABLE'
  | 'VAULT_FACTORS_INVALID'
  | 'VAULT_SUITE_UNSUPPORTED'
  | 'VAULT_TAMPERED'
  | 'VAULT_SECRET_REJECTED'
  | 'VAULT_PIN_REJECTED'

export type VaultErrorOptions = ErrorOptions & { code: VaultErrorCode }

export class VaultError extends Error {
  #code: VaultErrorCode

  constructor({ message, options }: VaultErrorParams) {
    super(message, options)
    this.name = 'VaultError'
    this.#code = options.code
  }

  get code(): VaultErrorCode {
    return this.#code
  }
}

export class NoAvailableFactor extends VaultError {
  #kind: string

  constructor({ kind }: NoAvailableFactorParams) {
    super({
      message: `No available vault factor of kind "${kind}" on this device`,
      options: {
        code: 'VAULT_FACTOR_UNAVAILABLE',
      },
    })

    this.name = 'NoAvailableFactor'
    this.#kind = kind
  }

  get kind(): string {
    return this.#kind
  }
}

export class InvalidVaultFactors extends VaultError {
  constructor({ reason }: InvalidVaultFactorsParams) {
    super({
      message: `Invalid vault factor list: ${reason}`,
      options: { code: 'VAULT_FACTORS_INVALID' },
    })
    this.name = 'InvalidVaultFactors'
  }
}

export class UnsupportedVaultSuite extends VaultError {
  #suite: number

  constructor({ suite }: UnsupportedVaultSuiteParams) {
    super({
      message: `Unsupported vault suite ${suite}`,
      options: { code: 'VAULT_SUITE_UNSUPPORTED' },
    })
    this.name = 'UnsupportedVaultSuite'
    this.#suite = suite
  }

  get suite(): number {
    return this.#suite
  }
}

export class VaultTampered extends VaultError {
  constructor({ message, options }: VaultTamperedParams) {
    super({ message, options: { ...options, code: 'VAULT_TAMPERED' } })
    this.name = 'VaultTampered'
  }
}

/** Authentication failed. The original GCM error is retained as cause. */
export class VaultSecretRejected extends VaultError {
  #kinds: Array<string>

  constructor({ kinds, options }: VaultSecretRejectedParams) {
    const keyID = options?.keyID

    super({
      message: `Vault ${kinds.join(' and ')} rejected${keyID == null ? '' : ` for key ${keyID}`}. If the secret is known to be correct, the wrapping's factor descriptors or ciphertext may have been altered -- the two are indistinguishable at this point.`,
      options: { ...options, code: options?.code ?? 'VAULT_SECRET_REJECTED' },
    })

    this.name = 'VaultSecretRejected'
    this.#kinds = kinds
  }

  get kinds(): Array<string> {
    return this.#kinds
  }
}

export class VaultPinRejected extends VaultSecretRejected {
  #attemptsRemaining: number
  #retryAfter: number

  constructor({ keyID, options }: VaultPinRejectedParams) {
    super({ kinds: ['pin'], options: { cause: options.cause, keyID, code: 'VAULT_PIN_REJECTED' } })
    this.name = 'VaultPinRejected'
    this.#attemptsRemaining = options.attemptsRemaining
    this.#retryAfter = options.retryAfter
  }

  get attemptsRemaining(): number {
    return this.#attemptsRemaining
  }

  get retryAfter(): number {
    return this.#retryAfter
  }
}
