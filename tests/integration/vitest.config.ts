import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    globalSetup: ['./src/global-setup.ts'],
    hookTimeout: 120_000,
    testTimeout: 60_000,
  },
})
