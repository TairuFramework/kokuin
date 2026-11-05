import { existsSync } from 'node:fs'
import { createRequire } from 'node:module'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

export type NapiVerifyParams = {
  es256: boolean
  signature: Uint8Array
  message: Uint8Array
  publicKey: Uint8Array
}

/** The ABI the provider expects from `crates/kokuin-crypto-napi` (its `ABI_VERSION`). */
export const NAPI_ABI_VERSION = 1

/** The shape of the native module built from `crates/kokuin-crypto-napi`. */
// napi-rs fixes these positional calls at the binary boundary.
type NativeNapiBinding = {
  ABI_VERSION: number
  sign(seed: Uint8Array, message: Uint8Array): Uint8Array
  signBatch(seeds: Array<Uint8Array>, messages: Array<Uint8Array>): Promise<Array<Uint8Array>>
  blake3(input: Uint8Array, length: number): Uint8Array
  blake3Batch(inputs: Array<Uint8Array>, length: number): Promise<Array<Uint8Array>>
  verify(es256: boolean, signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): boolean
  verifyBatch(
    es256: Array<boolean>,
    signatures: Array<Uint8Array>,
    messages: Array<Uint8Array>,
    publicKeys: Array<Uint8Array>,
  ): Promise<Array<boolean>>
}

function adaptBinding(native: NativeNapiBinding): NapiBinding {
  return {
    ABI_VERSION: native.ABI_VERSION,
    sign: ({ seed, message }) => native.sign(seed, message),
    // The native ABI takes parallel arrays. Split here so nothing above it can misalign entries.
    signBatch: (items) => {
      return native.signBatch(
        items.map((item) => item.seed),
        items.map((item) => item.message),
      )
    },
    blake3: ({ input, length }) => native.blake3(input, length),
    blake3Batch: ({ inputs, length }) => native.blake3Batch(inputs, length),
    verify: ({ es256, signature, message, publicKey }) => {
      return native.verify(es256, signature, message, publicKey)
    },
    verifyBatch: (items) => {
      return native.verifyBatch(
        items.map((item) => item.es256),
        items.map((item) => item.signature),
        items.map((item) => item.message),
        items.map((item) => item.publicKey),
      )
    },
  }
}

export type NapiBindingSignParams = { seed: Uint8Array; message: Uint8Array }
export type NapiBindingBlake3Params = { input: Uint8Array; length: number }
export type NapiBindingBlake3BatchParams = { inputs: Array<Uint8Array>; length: number }

export type NapiBinding = {
  ABI_VERSION: number
  sign(params: NapiBindingSignParams): Uint8Array
  verify(params: NapiVerifyParams): boolean
  blake3(params: NapiBindingBlake3Params): Uint8Array
  signBatch(items: Array<NapiBindingSignParams>): Promise<Array<Uint8Array>>
  verifyBatch(items: Array<NapiVerifyParams>): Promise<Array<boolean>>
  blake3Batch(params: NapiBindingBlake3BatchParams): Promise<Array<Uint8Array>>
}

/** Why no native binding loaded, or `undefined` when one did. */
export type NapiLoadFailure = { reason: 'missing' | 'abi' | 'load'; path: string; cause?: unknown }

function libc(): string {
  const header = (process.report?.getReport() as { header?: { glibcVersionRuntime?: string } })
    ?.header
  return header?.glibcVersionRuntime ? 'gnu' : 'musl'
}

/** The platform suffix of the binary file name, such as `linux-x64-gnu` or `darwin-arm64`. */
export function napiTarget(): string {
  const base = `${process.platform}-${process.arch}`
  return process.platform === 'linux' ? `${base}-${libc()}` : base
}

/** Where the binary for this platform is expected: `native/kokuin-crypto-napi.<target>.node`. */
export function napiBindingPath(): string {
  const root = join(dirname(fileURLToPath(import.meta.url)), '..')
  return join(root, 'native', `kokuin-crypto-napi.${napiTarget()}.node`)
}

let cached: { binding: NapiBinding | null; failure?: NapiLoadFailure } | undefined

/** Load the native binding once per process. Never throws; reports why it could not load. */
export function loadNapiBinding(): { binding: NapiBinding | null; failure?: NapiLoadFailure } {
  if (cached != null) return cached
  const path = napiBindingPath()
  if (!existsSync(path)) {
    cached = { binding: null, failure: { reason: 'missing', path } }
    return cached
  }
  try {
    const binding = createRequire(import.meta.url)(path) as NativeNapiBinding
    cached =
      binding.ABI_VERSION === NAPI_ABI_VERSION
        ? { binding: adaptBinding(binding) }
        : { binding: null, failure: { reason: 'abi', path } }
  } catch (cause) {
    cached = { binding: null, failure: { reason: 'load', path, cause } }
  }
  return cached
}
