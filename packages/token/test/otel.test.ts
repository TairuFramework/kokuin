import { trace } from '@opentelemetry/api'
import { InMemorySpanExporter, SimpleSpanProcessor, TracerProvider } from '@opentelemetry/sdk-trace'
import { afterAll, beforeAll, beforeEach, expect, test } from 'vitest'

import { randomIdentity } from '../src/identity.js'
import { verifyToken } from '../src/token.js'

let exporter: InMemorySpanExporter
let provider: TracerProvider

beforeAll(() => {
  exporter = new InMemorySpanExporter()
  provider = new TracerProvider({ spanProcessors: [new SimpleSpanProcessor({ exporter })] })
  trace.setGlobalTracerProvider(provider)
})
beforeEach(() => {
  exporter.reset()
})
afterAll(async () => {
  await provider.shutdown()
  trace.disable()
})

test('token sign + verify emit kokuin-prefixed spans with auth attrs', async () => {
  const identity = randomIdentity()
  const signed = await identity.signToken({ aud: 'someone' })
  await verifyToken(signed)

  await provider.forceFlush()
  const spans = exporter.getFinishedSpans()
  const names = spans.map((s) => s.name)

  expect(names).toContain('kokuin.token.sign')
  expect(names).toContain('kokuin.token.verify')

  const signSpan = spans.find((s) => s.name === 'kokuin.token.sign')
  expect(signSpan?.attributes['kokuin.auth.did']).toBe(identity.id)
  expect(signSpan?.attributes['kokuin.auth.algorithm']).toBe('EdDSA')

  const verifySpan = spans.find((s) => s.name === 'kokuin.token.verify')
  expect(verifySpan?.attributes['kokuin.auth.did']).toBe(identity.id)
})
