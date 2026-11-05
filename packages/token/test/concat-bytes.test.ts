import { expect, test } from 'vitest'

import { concatBytes } from '../src/index.js'

test('concatenates any number of parts in order', () => {
  expect(concatBytes()).toEqual(new Uint8Array())
  expect(concatBytes(new Uint8Array([1]))).toEqual(new Uint8Array([1]))
  expect(
    concatBytes(new Uint8Array([1, 2]), new Uint8Array(), new Uint8Array([3]), new Uint8Array([4])),
  ).toEqual(new Uint8Array([1, 2, 3, 4]))
})

test('returns a copy that does not alias its input', () => {
  const part = new Uint8Array([1])
  const out = concatBytes(part)
  part[0] = 9
  expect(out).toEqual(new Uint8Array([1]))
})
