import { runInNewContext } from 'node:vm'
import { expect, test } from 'vitest'

import { assertUnsharedBytes } from '../src/index.js'

test('accepts Node Buffers and offset views without copying', () => {
  for (const value of [Buffer.from([1, 2, 3]), new Uint8Array([0, 1, 2, 3]).subarray(1)]) {
    expect(() => assertUnsharedBytes(value)).not.toThrow()
  }
})

test('rejects other views and objects from any realm', () => {
  for (const expression of [
    'new Uint16Array([1, 2, 3])',
    'new Uint8ClampedArray([1, 2, 3])',
    'new DataView(new ArrayBuffer(3))',
    'new ArrayBuffer(3)',
    '({ [Symbol.toStringTag]: "Uint8Array", buffer: new ArrayBuffer(3) })',
    'null',
    'undefined',
  ]) {
    const value: Uint8Array = runInNewContext(expression)
    expect(() => assertUnsharedBytes(value)).toThrow('Expected an unshared Uint8Array')
  }
})
