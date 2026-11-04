import type { RecordClaim } from '../src/record.js'

export const claimFixture: RecordClaim = {
  type: 'test.value',
  id: '雪',
  owner: 'did:key:z6MkvDqGT54cXesYGvABpF1UapVNwjCqRcafi4Px6Thv5T3Z',
  hlc: '2026-01-01T00:00:00.000Z/0/node',
  payloadDigest: 'sXfsG_Jt-ztwENRz5tRHE7KbdluZxuYOy_rnQt5JZUM',
  deleted: false,
  meta: { nested: { z: 'é', a: [true, 2] }, version: '2025-01-01T00:00:00.000Z/0/node' },
}
export const CONTENT = 'AZh13nA3uBuBFMltBgUHtrCpV5GIsVJiiICgPIidm1c'
