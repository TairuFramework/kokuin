export type LedgerErrorParams = { message: string; statusCode: number }
export type LedgerDisconnectedErrorParams = { cause?: unknown }
export class LedgerError extends Error {
  #statusCode: number

  constructor({ message, statusCode }: LedgerErrorParams) {
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
    super({ message: 'User rejected the operation on Ledger device', statusCode: 0x6985 })
    this.name = 'LedgerUserRejectedError'
  }
}

export class LedgerDisconnectedError extends LedgerError {
  constructor({ cause }: LedgerDisconnectedErrorParams = {}) {
    super({ message: 'Ledger device disconnected', statusCode: 0 })
    this.name = 'LedgerDisconnectedError'
    if (cause != null) {
      this.cause = cause
    }
  }
}

export class LedgerAppNotOpenError extends LedgerError {
  constructor() {
    super({ message: 'Kokuin app not open on Ledger device', statusCode: 0x6a82 })
    this.name = 'LedgerAppNotOpenError'
  }
}
