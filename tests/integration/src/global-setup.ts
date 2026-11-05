import type { TestProject } from 'vitest/node'

import {
  type IntegrationContext,
  type PostgresServer,
  selectedBackends,
  startPostgres,
} from './backends.js'

type IntegrationProject = Omit<TestProject, 'provide'> & {
  provide<TKey extends keyof IntegrationContext>(key: TKey, value: IntegrationContext[TKey]): void
}

let server: PostgresServer | null = null

export async function setup(project: TestProject): Promise<void> {
  const contextProject = project as IntegrationProject
  server = selectedBackends().includes('postgres') ? await startPostgres() : null
  contextProject.provide('postgresURL', server?.url ?? null)
}

export async function teardown(): Promise<void> {
  await server?.stop()
  server = null
}
