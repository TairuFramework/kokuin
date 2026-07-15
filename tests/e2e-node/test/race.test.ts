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
  const results = await Promise.all(processes)
  return results.map((result) => JSON.parse(result.stdout))
}

/** The DID that actually survived in the OS keyring — the one any later process will load. */
function storedDID(keyID: string): string | null {
  const stored = new Entry(service, keyID).getPassword()
  return stored
}

describe('cross-process provideAsync', () => {
  // This test asserts the BUG. @napi-rs/keyring's write is an unconditional upsert with no
  // compare-and-set, so without a lock both processes observe null, both generate, both
  // write — and the loser holds a key that is no longer in the keychain. If this ever stops
  // failing this way, the race closed for some other reason and we want to know why.
  test('WITHOUT lockPath, the two processes can disagree — silent key loss', async () => {
    // Racing is nondeterministic; run several rounds and look for a single divergence.
    let diverged = false
    for (let round = 0; round < 12 && !diverged; round++) {
      const keyID = `unlocked-${round}`
      await writeFile(startFile, '').catch(() => undefined)
      await rm(startFile, { force: true })
      const [first, second] = await race(keyID)
      expect(first.error).toBeUndefined()
      expect(second.error).toBeUndefined()
      if (first.did !== second.did) {
        diverged = true
        // The loser signed with a key that is NOT what the keychain now holds.
        const survivor = storedDID(keyID)
        expect(survivor).not.toBeNull()
      }
    }
    expect(
      diverged,
      'expected at least one divergence across 12 unlocked rounds — if this fails, the race ' +
        'may have closed some other way, or the barrier is not releasing both processes together',
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
