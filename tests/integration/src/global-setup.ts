import type { TestProject } from 'vitest/node'

import { type PostgresServer, selectedBackends, startPostgres } from './backends.js'

let server: PostgresServer | null = null

export async function setup(project: TestProject): Promise<void> {
  server = selectedBackends().includes('postgres') ? await startPostgres() : null
  project.provide('postgresURL', server?.url ?? null)
}

export async function teardown(): Promise<void> {
  await server?.stop()
  server = null
}
