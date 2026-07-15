import HDKey from 'micro-key-producer/slip10.js'

const DEFAULT_BASE_PATH = "44'/876'"
const INDEX_RE = /^\d+$/
const HARDENED_SEGMENT_RE = /^\d+['h]$/

/**
 * SLIP-0010 ed25519 supports **hardened derivation only** — there is no public-key
 * derivation for ed25519, so a non-hardened segment is not a weaker key, it is not a key.
 * Reject it here rather than letting the derivation library decide.
 */
function assertHardened(path: string): void {
  if (path === 'm') {
    return
  }
  const segments = path.slice(2).split('/')
  for (const segment of segments) {
    if (!HARDENED_SEGMENT_RE.test(segment)) {
      throw new Error(
        `Invalid derivation path "${path}": segment "${segment}" is not hardened. ` +
          "SLIP-0010 ed25519 requires every segment to be hardened (e.g. 0' or 0h).",
      )
    }
  }
}

export function resolveDerivationPath(keyID: string, basePath: string = DEFAULT_BASE_PATH): string {
  if (keyID.startsWith('m/') || keyID === 'm') {
    assertHardened(keyID)
    return keyID
  }
  if (INDEX_RE.test(keyID)) {
    const path = `m/${basePath}/${keyID}'`
    assertHardened(path)
    return path
  }
  throw new Error(`Invalid keyID: "${keyID}" — expected a numeric index or full derivation path`)
}

export function derivePrivateKey(seed: Uint8Array, path: string): Uint8Array {
  const root = HDKey.fromMasterSeed(seed)
  if (path === 'm') {
    return root.privateKey
  }
  return root.derive(path).privateKey
}
