// Builds crates/kokuin-crypto-napi for this host and installs it where @kokuin/crypto-napi loads it:
// packages/crypto-napi/native/kokuin-crypto-napi.<target>.node. With --package, installs it into
// packages/crypto-napi-<target> instead, which is what a release publishes.
import { execFileSync } from 'node:child_process'
import { copyFileSync, mkdirSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
execFileSync(
  'pnpm',
  ['exec', 'cargo', 'build', '--release', '--locked', '--offline', '-p', 'kokuin-crypto-napi'],
  {
    cwd: root,
    stdio: 'inherit',
    // pnpm is a .cmd shim on Windows, which only a shell can run.
    shell: process.platform === 'win32',
  },
)
const library = {
  darwin: 'libkokuin_crypto_napi.dylib',
  linux: 'libkokuin_crypto_napi.so',
  win32: 'kokuin_crypto_napi.dll',
}[process.platform]
if (library == null) throw new Error(`Unsupported build host: ${process.platform}`)
const { napiTarget } = await import(join(root, 'packages/crypto-napi/lib/binding.js'))
const name = `kokuin-crypto-napi.${napiTarget()}.node`
const target = process.argv.includes('--package')
  ? join(root, `packages/crypto-napi-${napiTarget()}`, name)
  : join(root, 'packages/crypto-napi/native', name)
mkdirSync(dirname(target), { recursive: true })
copyFileSync(join(root, 'target/release', library), target)
console.log(`Installed ${target}`)
