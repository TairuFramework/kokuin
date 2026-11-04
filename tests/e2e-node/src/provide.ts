import { existsSync, writeFileSync } from 'node:fs'
import { NodeKeyStore } from '@kokuin/node'
import { AsyncEntry } from '@napi-rs/keyring'

const args = process.argv.slice(2)
if (args.length < 4) {
  throw new Error('usage: provide.ts <service> <keyID> <startFile> <readyFile> [lockPath]')
}
const [service, keyID, startFile, readyFile, lockPath] = args as [
  string,
  string,
  string,
  string,
  string?,
]

async function waitForStart(): Promise<void> {
  // Warm the keyring path first: the first async read spins up the thread pool and the D-Bus
  // session, and that one-off cost would otherwise skew which racer reads first.
  await new AsyncEntry(service, `${keyID}.warmup`).getPassword()
  // Announce readiness, then wait for the parent's start file. The parent waits for both ready
  // files first, so both processes enter provideAsync together instead of whenever each
  // finishes starting up.
  writeFileSync(readyFile, '')
  while (!existsSync(startFile)) {
    // Spin without sleeping: a timer tick of skew is enough for one racer's read to land after
    // the other's write, and then there is no race to observe.
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
