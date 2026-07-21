import { execFile } from 'node:child_process'
import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { promisify } from 'node:util'
import { Entry, findCredentials } from '@napi-rs/keyring'
import { afterEach, beforeEach, describe, expect, test } from 'vitest'

const run = promisify(execFile)
const CLI = new URL('../src/provide.ts', import.meta.url).pathname

let dir: string
let startFile: string
let service: string

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), 'kokuin-e2e-'))
  startFile = join(dir, 'start')
  service = `kokuin-e2e-${process.pid}-${Math.trunc(performance.now())}`
})

afterEach(async () => {
  // Leave no credentials behind in the developer's (or runner's) real keyring.
  for (const credential of findCredentials(service)) {
    new Entry(service, credential.account).deletePassword()
  }
  await rm(dir, { recursive: true, force: true })
})

/** Spawn two processes, release them together, and return what each one resolved to. */
async function race(
  keyID: string,
  lockPath?: string,
): Promise<Array<{ did?: string; error?: string }>> {
  const args = [service, keyID, startFile, ...(lockPath ? [lockPath] : [])]
  const processes = [
    run(process.execPath, ['--experimental-strip-types', CLI, ...args]),
    run(process.execPath, ['--experimental-strip-types', CLI, ...args]),
  ]
  // Both are now spinning on the start file. Release them at once.
  await writeFile(startFile, '')
  const settled = await Promise.all(
    processes.map((proc) =>
      proc.then(
        (result) => JSON.parse(result.stdout) as { did?: string; error?: string },
        // execFile rejects on a non-zero exit, but the CLI wrote its {error} JSON to stdout
        // before exit(1). Recover it from the rejection rather than letting Promise.all throw.
        (error: { stdout?: string }) =>
          (error.stdout != null ? JSON.parse(error.stdout) : { error: String(error) }) as {
            did?: string
            error?: string
          },
      ),
    ),
  )
  return settled
}

/** The DID that actually survived in the OS keyring — the one any later process will load. */
function storedDID(keyID: string): string | null {
  const stored = new Entry(service, keyID).getPassword()
  return stored
}

describe('cross-process provideAsync', () => {
  // This test asserts the BUG: without a lock, the concurrent create is unsafe. How that
  // manifests is platform-dependent. On Linux/gnome-keyring, @napi-rs/keyring's write is an
  // unconditional upsert with no compare-and-set, so both processes observe null, both
  // generate, both write — and the loser holds a key that is no longer in the keychain
  // ("divergence"). On macOS Keychain, the loser's create instead throws
  // errSecDuplicateItem, so one process succeeds and the other errors. Both are the same
  // underlying bug — an unguarded race on create — so either manifestation counts.
  test('WITHOUT lockPath, the unguarded concurrent create is unsafe', async () => {
    // Racing is nondeterministic; run several rounds and look for a single manifestation.
    let manifested = false
    for (let round = 0; round < 12 && !manifested; round++) {
      const keyID = `unlocked-${round}`
      await writeFile(startFile, '').catch(() => undefined)
      await rm(startFile, { force: true })
      const [first, second] = await race(keyID)

      const bothSucceeded = first.did != null && second.did != null
      const diverged = bothSucceeded && first.did !== second.did

      const duplicateErrors = [first, second].filter((result) =>
        /already exists|errSecDuplicate|duplicate item/i.test(result.error ?? ''),
      )
      const oneThrewDuplicate =
        duplicateErrors.length === 1 && (first.did != null || second.did != null)

      if (diverged || oneThrewDuplicate) {
        manifested = true
        // Whichever way it raced, a key survived in the OS keyring.
        expect(storedDID(keyID)).not.toBeNull()
      }
    }
    expect(
      manifested,
      'expected the unguarded race to manifest within 12 rounds — as diverging DIDs ' +
        '(Linux/gnome-keyring silent upsert) or as one racer throwing errSecDuplicateItem ' +
        '(macOS Keychain). If neither occurred, the barrier may not be releasing both ' +
        'processes together, or the platform serializes creates.',
    ).toBe(true)
  }, 60_000)

  test('WITH lockPath, both processes always agree on one identity', async () => {
    const lockPath = join(dir, 'keystore.lock')
    for (let round = 0; round < 12; round++) {
      const keyID = `locked-${round}`
      await rm(startFile, { force: true })
      const [first, second] = await race(keyID, lockPath)
      expect(first.error).toBeUndefined()
      expect(second.error).toBeUndefined()
      expect(second.did).toBe(first.did)
      expect(storedDID(keyID)).not.toBeNull()
    }
  }, 60_000)
})
