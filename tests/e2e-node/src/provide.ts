import { existsSync } from 'node:fs'
import { setTimeout as sleep } from 'node:timers/promises'

import { NodeKeyStore } from '@kokuin/node'

const [service, keyID, startFile, lockPath] = process.argv.slice(2)

async function waitForStart(): Promise<void> {
  // Spin until the parent drops the start file, so both processes enter provideAsync together.
  // Without this the first process finishes before the second begins, and there is no race.
  while (!existsSync(startFile)) {
    await sleep(2)
  }
}

async function main(): Promise<void> {
  const store = NodeKeyStore.open(lockPath ? { service, lockPath } : { service })
  await waitForStart()
  const identity = await store.provideIdentity(keyID)
  process.stdout.write(JSON.stringify({ did: identity.id }))
}

main().catch((error) => {
  process.stdout.write(JSON.stringify({ error: String(error) }))
  process.exit(1)
})
