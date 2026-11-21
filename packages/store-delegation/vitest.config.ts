import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    globalSetup: ['../../tests/integration/src/global-setup.ts'],
    hookTimeout: 120_000,
    testTimeout: 60_000,
  },
})
