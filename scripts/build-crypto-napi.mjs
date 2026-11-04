// Builds crates/kokuin-crypto-napi for this host and installs it where @kokuin/crypto-napi loads it:
// packages/crypto-napi/native/kokuin-crypto-napi.<target>.node. Prebuilt per-platform packages
// replace this for published installs.
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
  },
)
const library = {
  darwin: 'libkokuin_crypto_napi.dylib',
  linux: 'libkokuin_crypto_napi.so',
  win32: 'kokuin_crypto_napi.dll',
}[process.platform]
if (library == null) throw new Error(`Unsupported build host: ${process.platform}`)
const { napiBindingPath } = await import(join(root, 'packages/crypto-napi/lib/binding.js'))
const target = napiBindingPath()
mkdirSync(dirname(target), { recursive: true })
copyFileSync(join(root, 'target/release', library), target)
console.log(`Installed ${target}`)
