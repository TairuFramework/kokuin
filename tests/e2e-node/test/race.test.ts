import { execFile } from 'node:child_process'
import { existsSync } from 'node:fs'
import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { setTimeout as sleep } from 'node:timers/promises'
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
  const readyFiles = [join(dir, `${keyID}.ready-0`), join(dir, `${keyID}.ready-1`)]
  const processes = readyFiles.map((readyFile) => {
    return run(process.execPath, [
      '--experimental-strip-types',
      CLI,
      service,
      keyID,
      startFile,
      readyFile,
      ...(lockPath ? [lockPath] : []),
    ])
  })
  // Release only once both processes have started and are spinning on the start file. Writing it
  // straight after spawning lets each one through as soon as it boots, so startup jitter decides
  // the order and the creates often never overlap.
  let exited = false
  for (const proc of processes) {
    proc.then(
      () => {
        exited = true
      },
      () => {
        exited = true
      },
    )
  }
  const deadline = Date.now() + 20_000
  while (!readyFiles.every((file) => existsSync(file))) {
    if (exited || Date.now() > deadline) {
      // Release any racer still spinning so it does not outlive the test.
      await writeFile(startFile, '')
      await Promise.allSettled(processes)
      throw new Error(exited ? 'a racer exited before reporting ready' : 'racers not ready in 20s')
    }
    await sleep(2)
  }
  await writeFile(startFile, '')
  const settled = await Promise.all(
    processes.map((proc) => {
      return proc.then(
        (result) => JSON.parse(result.stdout) as { did?: string; error?: string },
        // execFile rejects on a non-zero exit, but the CLI wrote its {error} JSON to stdout
        // before exit(1). Recover it from the rejection rather than letting Promise.all throw.
        (error: { stdout?: string }) => {
          return (error.stdout != null ? JSON.parse(error.stdout) : { error: String(error) }) as {
            did?: string
            error?: string
          }
        },
      )
    }),
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
    for (let round = 0; round < 24 && !manifested; round++) {
      const keyID = `unlocked-${round}`
      await rm(startFile, { force: true })
      const [first, second] = await race(keyID)

      const bothSucceeded = first.did != null && second.did != null
      const diverged = bothSucceeded && first.did !== second.did

      const duplicateErrors = [first, second].filter((result) => {
        return /already exists|errSecDuplicate|duplicate item/i.test(result.error ?? '')
      })
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
      'expected the unguarded race to manifest within 24 rounds — as diverging DIDs ' +
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
