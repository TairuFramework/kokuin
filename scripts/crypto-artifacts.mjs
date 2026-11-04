import { createHash } from 'node:crypto'
import { readdirSync, readFileSync, writeFileSync } from 'node:fs'
import { join, relative } from 'node:path'

function files(directory) {
  return readdirSync(directory, { withFileTypes: true })
    .flatMap((entry) => {
      const path = join(directory, entry.name)
      return entry.isDirectory() ? files(path) : [path]
    })
    .sort()
}

export function sourceFingerprint(root) {
  const sources = [
    'Cargo.toml',
    'Cargo.lock',
    'rust-toolchain.toml',
    'scripts/build-crypto-native.mjs',
    'scripts/crypto-artifacts.mjs',
  ].map((path) => join(root, path))
  sources.push(...files(join(root, 'crates')).filter((path) => /\.(rs|toml)$/.test(path)))
  const hash = createHash('sha256')
  for (const path of sources.sort()) {
    const name = relative(root, path)
    const content = readFileSync(path)
    hash.update(`${name.length}:${name}:${content.length}:`)
    hash.update(content)
  }
  return hash.digest('hex')
}

function artifactRoot(root, platform) {
  return join(
    root,
    'packages/crypto-native/prebuilt',
    platform === 'ios' ? 'ios/KokuinCrypto.xcframework' : 'android',
  )
}

function manifestPath(root, platform) {
  return join(root, 'packages/crypto-native/prebuilt', `${platform}.json`)
}

function artifactHashes(root, platform) {
  const directory = artifactRoot(root, platform)
  return Object.fromEntries(
    files(directory).map((path) => [
      relative(directory, path),
      createHash('sha256').update(readFileSync(path)).digest('hex'),
    ]),
  )
}

export function stampArtifacts(root, platform, fingerprint) {
  if (sourceFingerprint(root) !== fingerprint)
    throw new Error('Crypto sources changed during the native build. Rebuild before benchmarking.')
  writeFileSync(
    manifestPath(root, platform),
    `${JSON.stringify({ sourceFingerprint: fingerprint, files: artifactHashes(root, platform) }, null, 2)}\n`,
  )
}

export function artifactsCurrent(root, platform) {
  try {
    const manifest = JSON.parse(readFileSync(manifestPath(root, platform), 'utf8'))
    const hashes = artifactHashes(root, platform)
    const required =
      platform === 'ios'
        ? [
            'Info.plist',
            'ios-arm64/libkokuin_crypto_ffi.a',
            'ios-arm64_x86_64-simulator/libkokuin_crypto_ffi.a',
          ]
        : ['arm64-v8a/libkokuin_crypto_ffi.a', 'x86_64/libkokuin_crypto_ffi.a']
    return (
      manifest.sourceFingerprint === sourceFingerprint(root) &&
      required.every((path) => hashes[path] !== undefined) &&
      JSON.stringify(manifest.files) === JSON.stringify(hashes)
    )
  } catch {
    return false
  }
}
