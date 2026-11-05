// Installs the packed packages into an empty directory, as a consumer would, and checks the backend
// on this host: `napi` with the platform package, `node` when optional dependencies are omitted.
// The platform package must already hold its binary (build-crypto-napi.mjs --package).
import { execSync } from 'node:child_process'
import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const { napiTarget } = await import(join(root, 'packages/crypto-napi/lib/binding.js'))
const platformPackage = `@kokuin/crypto-napi-${napiTarget()}`
const work = mkdtempSync(join(tmpdir(), 'crypto-napi-smoke-'))

function pack(directory) {
  const output = execSync(`pnpm pack --pack-destination "${work}"`, {
    cwd: directory,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'inherit'],
  })
  return output.trim().split('\n').at(-1)
}

const crypto = pack(join(root, 'packages/crypto'))
const cryptoNode = pack(join(root, 'packages/crypto-node'))
const binary = pack(join(root, `packages/crypto-napi-${napiTarget()}`))

// The other platforms' packages are not on the registry until this version is released.
const napiSource = join(work, 'napi-source')
mkdirSync(napiSource)
const napiManifest = JSON.parse(
  readFileSync(join(root, 'packages/crypto-napi/package.json'), 'utf8'),
)
cpSync(join(root, 'packages/crypto-napi/lib'), join(napiSource, 'lib'), { recursive: true })
napiManifest.dependencies = { '@kokuin/crypto': crypto, '@kokuin/crypto-node': cryptoNode }
napiManifest.optionalDependencies = { [platformPackage]: binary }
delete napiManifest.scripts
delete napiManifest.devDependencies
writeFileSync(join(napiSource, 'package.json'), JSON.stringify(napiManifest))

const check = `
import { createNapiCrypto } from '@kokuin/crypto-napi'
const crypto = createNapiCrypto()
const privateKey = new Uint8Array(32).fill(7)
const message = new TextEncoder().encode('smoke')
const signature = await crypto.sign({ alg: 'EdDSA', privateKey, message })
const digest = await crypto.blake3({ input: message, dkLen: 32 })
if (signature.length !== 64 || digest.length !== 32) throw new Error('Unexpected output')
console.log(JSON.stringify({ backend: crypto.backend, failure: crypto.failure }))
`

function install(omitOptional) {
  const app = join(work, omitOptional ? 'app-without-optional' : 'app')
  mkdirSync(app)
  writeFileSync(
    join(app, 'package.json'),
    JSON.stringify({
      name: 'smoke',
      private: true,
      type: 'module',
      dependencies: { '@kokuin/crypto-napi': napiSource },
      overrides: { '@kokuin/crypto': crypto, '@kokuin/crypto-node': cryptoNode },
    }),
  )
  writeFileSync(join(app, 'check.mjs'), check)
  const omit = omitOptional ? ' --omit=optional' : ''
  execSync(`npm install --no-audit --no-fund --install-links${omit}`, {
    cwd: app,
    stdio: 'inherit',
  })
  return JSON.parse(execSync('node check.mjs', { cwd: app, encoding: 'utf8' }))
}

const withBinary = install(false)
const withoutBinary = install(true)
rmSync(work, { recursive: true, force: true })
console.log({ withBinary, withoutBinary })
if (withBinary.backend !== 'napi')
  throw new Error(`Expected napi, got ${JSON.stringify(withBinary)}`)
if (withoutBinary.backend !== 'node' || withoutBinary.failure?.reason !== 'missing') {
  throw new Error(`Expected a node fallback, got ${JSON.stringify(withoutBinary)}`)
}
