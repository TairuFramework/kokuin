import { runInNewContext } from 'node:vm'
import { expect, test } from 'vitest'

import { snapshotData } from '../src/snapshot.js'

test('copies byte inputs from another realm into owned storage', () => {
  const input: Uint8Array = runInNewContext('new Uint8Array([1, 2, 3])')
  expect(input instanceof Uint8Array).toBe(false)
  const result = snapshotData(input)
  expect(result).toEqual(snapshotData(new Uint8Array([1, 2, 3])))
  input.fill(0)
  expect(result).toEqual(new Uint8Array([1, 2, 3]))
})

test('copies shared byte inputs into unshared storage', () => {
  const foreign: Uint8Array = runInNewContext('new Uint8Array(new SharedArrayBuffer(3))')
  for (const input of [new Uint8Array(new SharedArrayBuffer(3)), foreign]) {
    input.set([1, 2, 3])
    const result = snapshotData(input)
    expect(result.buffer).toBeInstanceOf(ArrayBuffer)
    input.fill(0)
    expect(result).toEqual(new Uint8Array([1, 2, 3]))
  }
})
