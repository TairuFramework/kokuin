# integration-tests

Kokuin store integration tests against real node:sqlite files and a real Postgres server.
They run the shared `@kokuin/store-controller` and `@kokuin/store-delegation` cases, pin the
legacy `tablePrefix: 'kubun'` physical names, and race concurrent writers on Postgres.

The store packages are loaded from their built `lib/`. Build them before a run.

```sh
pnpm run test:integration                      # from the repo root; Docker running
KOKUIN_INTEGRATION_BACKENDS=node-sqlite pnpm run test:integration   # no Postgres
```

Postgres comes from `KOKUIN_POSTGRES_URL` when set, otherwise from a testcontainers
`postgres:18-alpine`. Without either, Postgres tests are skipped with a notice locally and
fail when `CI=true`. Every `createAdapter()` call creates a separate database. For repeated
local runs, start the bundled server once:

```sh
docker compose up -d --wait
KOKUIN_POSTGRES_URL=postgres://postgres:kokuin@localhost:5432/postgres pnpm run test:integration
```
