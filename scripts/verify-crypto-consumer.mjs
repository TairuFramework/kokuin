import assert from 'node:assert/strict'
import { execFileSync, spawnSync } from 'node:child_process'
import { cpSync, mkdirSync, mkdtempSync, readFileSync, symlinkSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

import { nativePackageFiles } from './check-crypto-package.mjs'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const directory = mkdtempSync(join(tmpdir(), 'kokuin-crypto-consumer-'))
const packages = join(directory, 'packages')
mkdirSync(packages)

function run(command, args, cwd = root, env = process.env) {
  execFileSync(command, args, { cwd, env, stdio: 'inherit' })
}

const tarballs = {}
for (const name of ['crypto', 'crypto-native', 'crypto-conformance']) {
  run('pnpm', ['--dir', `packages/${name}`, 'pack', '--pack-destination', packages])
  const manifest = JSON.parse(readFileSync(join(root, `packages/${name}/package.json`), 'utf8'))
  tarballs[`@kokuin/${name}`] = join(packages, `kokuin-${name}-${manifest.version}.tgz`)
}
const nativeArchive = tarballs['@kokuin/crypto-native']
const contents = execFileSync('tar', ['-tf', nativeArchive], { encoding: 'utf8' })
for (const name of nativePackageFiles)
  assert.ok(contents.split('\n').includes(`package/${name}`), `Missing packed file: ${name}`)
assert.ok(!contents.includes('/cpp/test/'), 'Packed native test sources')
assert.ok(!contents.includes('Cargo.toml'), 'Packed Rust build workspace')
for (const archive of Object.values(tarballs)) {
  const manifest = execFileSync('tar', ['-xOf', archive, 'package/package.json'], {
    encoding: 'utf8',
  })
  assert.ok(!/workspace:|file:|link:/.test(manifest), 'Unresolved local dependency in tarball')
}

// Consumer builds can use normal host tools, but cannot invoke a Rust toolchain.
const bin = join(directory, 'bin')
mkdirSync(bin)
for (const name of [
  'node',
  'pnpm',
  'git',
  'pod',
  'ruby',
  'java',
  'javac',
  'watchman',
  'ninja',
  'cmake',
  'python3',
]) {
  try {
    const path = execFileSync('which', [name], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
    }).trim()
    symlinkSync(path, join(bin, name))
  } catch {
    // Optional platform tools are only needed when that platform's fixture is built.
  }
}
const env = { ...process.env, PATH: `${bin}:/usr/bin:/bin:/usr/sbin:/sbin`, CI: '1' }
assert.equal(spawnSync('cargo', ['--version'], { env }).error?.code, 'ENOENT')

function fixture(name, dependencies) {
  const path = join(directory, name)
  mkdirSync(path)
  writeFileSync(
    join(path, 'package.json'),
    `${JSON.stringify({ name: `kokuin-crypto-${name}`, version: '1.0.0', private: true, type: 'module', dependencies }, null, 2)}\n`,
  )
  writeFileSync(
    join(path, 'pnpm-workspace.yaml'),
    `packages: []\nnodeLinker: hoisted\noverrides:\n  '@kokuin/crypto': 'file:${tarballs['@kokuin/crypto']}'\n`,
  )
  return path
}

const portable = fixture('portable', { '@kokuin/crypto': `file:${tarballs['@kokuin/crypto']}` })
cpSync(join(root, 'scripts/crypto-consumer/portable.mjs'), join(portable, 'check.mjs'))
run('pnpm', ['install', '--ignore-scripts'], portable, env)
run(process.execPath, ['check.mjs'], portable, env)

const installedVersion = (name) =>
  JSON.parse(readFileSync(join(root, 'node_modules', name, 'package.json'), 'utf8')).version
const mobile = fixture('mobile', {
  ...Object.fromEntries(Object.entries(tarballs).map(([name, path]) => [name, `file:${path}`])),
  expo: installedVersion('expo'),
  react: installedVersion('react'),
  'react-native': installedVersion('react-native'),
  'react-native-nitro-modules': installedVersion('react-native-nitro-modules'),
})
const manifestPath = join(mobile, 'package.json')
const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'))
manifest.main = 'index.ts'
manifest.scripts = {
  'ios:release': 'expo run:ios --configuration Release --no-bundler',
  'android:release': 'expo run:android --variant release --no-bundler',
}
writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`)
writeFileSync(
  join(mobile, 'index.ts'),
  "import { registerRootComponent } from 'expo'\nimport App from './App'\nregisterRootComponent(App)\n",
)
writeFileSync(
  join(mobile, 'app.json'),
  `${JSON.stringify({ expo: { name: 'CryptoConsumer', slug: 'crypto-consumer', ios: { bundleIdentifier: 'com.kokuin.cryptoconsumer' }, android: { package: 'com.kokuin.cryptoconsumer' } } }, null, 2)}\n`,
)
cpSync(join(root, 'scripts/crypto-consumer/App.tsx'), join(mobile, 'App.tsx'))
run('pnpm', ['install', '--ignore-scripts'], mobile, env)
writeFileSync(
  join(directory, 'environment.json'),
  `${JSON.stringify({ PATH: env.PATH, CI: '1' }, null, 2)}\n`,
)
console.log(
  JSON.stringify({ directory, portable, mobile, consumerPATH: env.PATH, tarballs }, null, 2),
)
