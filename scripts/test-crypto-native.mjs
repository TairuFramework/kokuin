import { execFileSync } from 'node:child_process'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const directory = mkdtempSync(join(tmpdir(), 'kokuin-native-test-'))
try {
  execFileSync(
    'pnpm',
    ['exec', 'cargo', 'build', '-p', 'kokuin-crypto-ffi', '--locked', '--offline'],
    {
      cwd: root,
      stdio: 'inherit',
    },
  )
  const binary = join(directory, 'ownership-test')
  execFileSync(
    'c++',
    [
      '-std=c++20',
      '-Wall',
      '-Wextra',
      '-Werror',
      '-fsanitize=address,undefined',
      '-I',
      join(root, 'packages/crypto-native/cpp'),
      join(root, 'packages/crypto-native/cpp/test/OwnershipTest.cpp'),
      '-o',
      binary,
    ],
    { stdio: 'inherit' },
  )
  execFileSync(binary, [], { stdio: 'inherit' })
  const worker = join(directory, 'worker-test')
  const libraries =
    process.platform === 'darwin'
      ? ['-framework', 'Security', '-lresolv', '-liconv']
      : ['-ldl', '-lpthread', '-lm']
  execFileSync(
    'c++',
    [
      '-std=c++20',
      '-Wall',
      '-Wextra',
      '-Werror',
      '-fsanitize=address,undefined',
      '-I',
      join(root, 'packages/crypto-native/cpp'),
      join(root, 'packages/crypto-native/cpp/test/WorkerTest.cpp'),
      join(root, 'target/debug/libkokuin_crypto_ffi.a'),
      ...libraries,
      '-o',
      worker,
    ],
    { stdio: 'inherit' },
  )
  execFileSync(worker, [], { stdio: 'inherit' })
} finally {
  rmSync(directory, { recursive: true, force: true })
}
