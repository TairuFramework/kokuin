export class LedgerError extends Error {
  #statusCode: number

  constructor(message: string, statusCode: number) {
    super(message)
    this.name = 'LedgerError'
    this.#statusCode = statusCode
  }

  get statusCode(): number {
    return this.#statusCode
  }
}

export class LedgerUserRejectedError extends LedgerError {
  constructor() {
    super('User rejected the operation on Ledger device', 0x6985)
    this.name = 'LedgerUserRejectedError'
  }
}

export class LedgerDisconnectedError extends LedgerError {
  constructor(cause?: unknown) {
    super('Ledger device disconnected', 0)
    this.name = 'LedgerDisconnectedError'
    if (cause != null) {
      this.cause = cause
    }
  }
}

export class LedgerAppNotOpenError extends LedgerError {
  constructor() {
    super('Kokuin app not open on Ledger device', 0x6a82)
    this.name = 'LedgerAppNotOpenError'
  }
}
