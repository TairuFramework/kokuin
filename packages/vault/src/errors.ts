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

  constructor(message: string, options: VaultErrorOptions) {
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

  constructor(kind: string) {
    super(`No available vault factor of kind "${kind}" on this device`, {
      code: 'VAULT_FACTOR_UNAVAILABLE',
    })

    this.name = 'NoAvailableFactor'
    this.#kind = kind
  }

  get kind(): string {
    return this.#kind
  }
}

export class InvalidVaultFactors extends VaultError {
  constructor(reason: string) {
    super(`Invalid vault factor list: ${reason}`, { code: 'VAULT_FACTORS_INVALID' })
    this.name = 'InvalidVaultFactors'
  }
}

export class UnsupportedVaultSuite extends VaultError {
  #suite: number

  constructor(suite: number) {
    super(`Unsupported vault suite ${suite}`, { code: 'VAULT_SUITE_UNSUPPORTED' })
    this.name = 'UnsupportedVaultSuite'
    this.#suite = suite
  }

  get suite(): number {
    return this.#suite
  }
}

export class VaultTampered extends VaultError {
  constructor(message: string, options?: ErrorOptions) {
    super(message, { ...options, code: 'VAULT_TAMPERED' })
    this.name = 'VaultTampered'
  }
}

/** Authentication failed. The original GCM error is retained as cause. */
export class VaultSecretRejected extends VaultError {
  #kinds: Array<string>

  constructor(
    kinds: Array<string>,
    options?: ErrorOptions & { keyID?: string; code?: VaultErrorCode },
  ) {
    const keyID = options?.keyID

    super(
      `Vault ${kinds.join(' and ')} rejected${keyID == null ? '' : ` for key ${keyID}`}. If the secret is known to be correct, the wrapping's factor descriptors or ciphertext may have been altered -- the two are indistinguishable at this point.`,
      { ...options, code: options?.code ?? 'VAULT_SECRET_REJECTED' },
    )

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

  constructor(
    keyID: string,
    options: ErrorOptions & { attemptsRemaining: number; retryAfter: number },
  ) {
    super(['pin'], { cause: options.cause, keyID, code: 'VAULT_PIN_REJECTED' })
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
