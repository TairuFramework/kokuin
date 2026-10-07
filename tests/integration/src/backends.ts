import { randomUUID } from 'node:crypto'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import type { Adapter } from '@hozon/adapter'
import { NodeSQLiteAdapter, type SQLitePragmas } from '@hozon/node-sqlite'
import { PostgresAdapter, type PostgresAdapterParams } from '@hozon/postgres'
import postgres from 'postgres'
import { inject } from 'vitest'

export type BackendName = 'node-sqlite' | 'postgres'

export type OpenOptions = {
  /** node-sqlite only. */
  pragmas?: SQLitePragmas
  /** Postgres only, merged over the backend's defaults. */
  postgres?: PostgresAdapterParams['options']
}

export type Backend = {
  name: BackendName
  /** Creates a fresh, empty database and opens an adapter on it. */
  createAdapter(options?: OpenOptions): Promise<Adapter>
  /** Opens another adapter on the database created last. */
  reopen(options?: OpenOptions): Promise<Adapter>
  /** File path or connection URL of the database created last. */
  location(): string
  /** Closes every adapter opened through this backend and removes every database it created. */
  cleanup(): Promise<void>
}

declare module 'vitest' {
  // biome-ignore lint/style/useConsistentTypeDefinitions: module augmentation needs an interface.
  interface ProvidedContext {
    postgresURL: string | null
  }
}

const BACKEND_NAMES: Array<BackendName> = ['node-sqlite', 'postgres']

/** Backends named by `KOKUIN_INTEGRATION_BACKENDS` (comma-separated), both by default. */
export function selectedBackends(): Array<BackendName> {
  const value = process.env.KOKUIN_INTEGRATION_BACKENDS?.trim()
  if (!value) return BACKEND_NAMES
  const names = value.split(',').map((name) => name.trim())
  for (const name of names) {
    if (!BACKEND_NAMES.includes(name as BackendName)) {
      throw new Error(`Unknown KOKUIN_INTEGRATION_BACKENDS entry "${name}"`)
    }
  }
  return BACKEND_NAMES.filter((name) => names.includes(name))
}

export type PostgresServer = { url: string; stop(): Promise<void> }

/**
 * Resolves the Postgres server for the run: `KOKUIN_POSTGRES_URL` when set, otherwise a
 * testcontainers `postgres:18-alpine`. Returns `null` (Postgres skipped) when neither is
 * available, and throws instead when `CI=true`.
 */
export async function startPostgres(): Promise<PostgresServer | null> {
  const url = process.env.KOKUIN_POSTGRES_URL?.trim()
  if (url) return { url, stop: async () => {} }
  try {
    const { PostgreSqlContainer } = await import('@testcontainers/postgresql')
    const container = await new PostgreSqlContainer('postgres:18-alpine').start()
    return {
      url: container.getConnectionUri(),
      stop: async () => {
        await container.stop()
      },
    }
  } catch (cause) {
    if (process.env.CI === 'true') {
      throw new Error('Postgres is required when CI=true: set KOKUIN_POSTGRES_URL or run Docker', {
        cause,
      })
    }
    const reason = cause instanceof Error ? cause.message : String(cause)
    console.warn(
      `[integration] Postgres tests SKIPPED: KOKUIN_POSTGRES_URL is unset and no container could start (${reason})`,
    )
    return null
  }
}

function createNodeSQLiteBackend(): Backend {
  const directories: Array<string> = []
  const adapters: Array<NodeSQLiteAdapter> = []
  let current: string | undefined
  const open = (options: OpenOptions = {}): NodeSQLiteAdapter => {
    if (current === undefined) throw new Error('No database created yet')
    const adapter = new NodeSQLiteAdapter({ database: current, pragmas: options.pragmas })
    adapters.push(adapter)
    return adapter
  }
  return {
    name: 'node-sqlite',
    async createAdapter(options) {
      const directory = await mkdtemp(join(tmpdir(), 'kokuin-integration-'))
      directories.push(directory)
      current = join(directory, 'kokuin.db')
      return open(options)
    },
    async reopen(options) {
      return open(options)
    },
    location() {
      return current ?? fail('No database created yet')
    },
    async cleanup() {
      await Promise.all(adapters.splice(0).map((adapter) => adapter.close()))
      await Promise.all(
        directories.splice(0).map((directory) => rm(directory, { recursive: true, force: true })),
      )
      current = undefined
    },
  }
}

function createPostgresBackend(serverURL: string): Backend {
  const databases: Array<string> = []
  const adapters: Array<PostgresAdapter> = []
  let admin: postgres.Sql | undefined
  let current: string | undefined
  const getAdmin = (): postgres.Sql => {
    admin ??= postgres(serverURL, { max: 1, onnotice: () => {} })
    return admin
  }
  const open = (options: OpenOptions = {}): PostgresAdapter => {
    if (current === undefined) throw new Error('No database created yet')
    const adapter = new PostgresAdapter({
      url: current,
      options: { onnotice: () => {}, ...options.postgres },
    })
    adapters.push(adapter)
    return adapter
  }
  return {
    name: 'postgres',
    async createAdapter(options) {
      const name = `kokuin_test_${randomUUID().replaceAll('-', '')}`
      await getAdmin().unsafe(`CREATE DATABASE "${name}"`)
      databases.push(name)
      const url = new URL(serverURL)
      url.pathname = `/${name}`
      current = url.toString()
      return open(options)
    },
    async reopen(options) {
      return open(options)
    },
    location() {
      return current ?? fail('No database created yet')
    },
    async cleanup() {
      await Promise.all(adapters.splice(0).map((adapter) => adapter.close()))
      for (const name of databases.splice(0)) {
        await getAdmin().unsafe(`DROP DATABASE IF EXISTS "${name}" WITH (FORCE)`)
      }
      await admin?.end({ timeout: 5 })
      admin = undefined
      current = undefined
    },
  }
}

function fail(message: string): never {
  throw new Error(message)
}

/**
 * The backends of this run, for `describe.each`. Postgres is absent when it was not
 * selected or no server was available (see `startPostgres`).
 */
export function backends(): Array<Backend> {
  const postgresURL = inject('postgresURL')
  return selectedBackends().flatMap((name): Array<Backend> => {
    if (name === 'node-sqlite') return [createNodeSQLiteBackend()]
    return postgresURL == null ? [] : [createPostgresBackend(postgresURL)]
  })
}

/** Backends restricted to `names`, for scenarios that apply to one backend only. */
export function backendsNamed(...names: Array<BackendName>): Array<Backend> {
  return backends().filter((backend) => names.includes(backend.name))
}
