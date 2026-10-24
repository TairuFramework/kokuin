import { describe, expect, test } from 'vitest'

import { CONCURRENCY_LIMIT, settleLimited } from '../src/limit.js'

describe('settleLimited', () => {
  test('runs at most the limit at once, starts in order and keeps result order', async () => {
    let active = 0
    let peak = 0
    const started: Array<number> = []
    const items = Array.from({ length: 50 }, (_, index) => index)
    const results = await settleLimited(items, async (item) => {
      started.push(item)
      active += 1
      peak = Math.max(peak, active)
      await new Promise((resolve) => setTimeout(resolve, item % 3))
      active -= 1
      if (item === 7) throw new Error('seven')
      return item * 2
    })

    expect(peak).toBe(CONCURRENCY_LIMIT)
    expect(started).toEqual(items)
    expect(results[7]).toMatchObject({ status: 'rejected' })
    expect(results.filter((result) => result.status === 'fulfilled')).toHaveLength(49)
    expect(results[8]).toEqual({ status: 'fulfilled', value: 16 })
    expect(await settleLimited([], async () => 1)).toEqual([])
  })
})
