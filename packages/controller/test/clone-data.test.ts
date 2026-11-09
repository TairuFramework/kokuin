import { runInNewContext } from 'node:vm'
import { describe, expect, test } from 'vitest'

import { cloneData } from '../src/clone-data.js'

function present<TValue>(value: TValue | undefined): TValue {
  if (value === undefined) throw new Error('Missing fixture value')
  return value
}

describe('cloneData', () => {
  test('copies Uint8Arrays from another realm', () => {
    const foreign = runInNewContext('new Uint8Array([1, 2, 3])') as Uint8Array
    const copy = cloneData({ key: foreign })
    expect(copy.key).not.toBe(foreign)
    expect(Array.from(copy.key)).toEqual([1, 2, 3])
    foreign[0] = 9
    expect(copy.key[0]).toBe(1)
  })

  test('preserves primitives including bigint, undefined and non-finite numbers', () => {
    for (const value of [
      null,
      undefined,
      true,
      false,
      'value',
      0,
      -0,
      7,
      1n,
      Number.NaN,
      Number.POSITIVE_INFINITY,
    ]) {
      expect(cloneData(value)).toBe(value)
    }
  })

  test('copies Uint8Array views without retaining caller bytes', () => {
    const source = new Uint8Array([0, 1, 2, 3]).subarray(1, 3)
    const owned = cloneData(source)
    expect(owned).toBeInstanceOf(Uint8Array)
    expect([...owned]).toEqual([1, 2])
    source[0] = 9
    owned[1] = 8
    expect([...owned]).toEqual([1, 8])
    expect([...source]).toEqual([9, 2])
  })

  test('copies nested arrays and plain objects while retaining undefined properties and holes', () => {
    const source = { entries: [{ value: 7, optional: undefined }], sparse: new Array<unknown>(2) }
    source.sparse[1] = undefined
    const owned = cloneData(source)
    expect(Object.hasOwn(present(owned.entries[0]), 'optional')).toBe(true)
    expect(Object.hasOwn(owned.sparse, 0)).toBe(false)
    expect(Object.hasOwn(owned.sparse, 1)).toBe(true)
    expect(owned.sparse).toHaveLength(2)
    present(source.entries[0]).value = 8
    expect(owned.entries).toEqual([{ value: 7, optional: undefined }])
    present(owned.entries[0]).value = 9
    expect(source.entries[0]?.value).toBe(8)
  })

  test('preserves aliases and cycles across objects, Map keys and Set values within the owned copy', () => {
    const shared = { nested: [7] }
    const source = {
      shared,
      map: new Map([[shared, { shared }]]),
      set: new Set([shared]),
      bytes: new Uint8Array([1]),
    }
    const graph = { source, again: source, cycle: new Set<unknown>() }
    graph.cycle.add(graph)
    const owned = cloneData(graph)
    expect(owned.source).not.toBe(source)
    expect(owned.again).toBe(owned.source)
    expect(owned.cycle.has(owned)).toBe(true)
    const key = present([...owned.source.map.keys()][0])
    expect(key).toBe(owned.source.shared)
    expect(owned.source.map.get(key)?.shared).toBe(key)
    expect(owned.source.set.has(key)).toBe(true)
    source.shared.nested[0] = 8
    expect(key.nested).toEqual([7])
    key.nested[0] = 9
    expect(shared.nested).toEqual([8])
    const bytes = cloneData({ first: source.bytes, second: source.bytes })
    expect(bytes.first).toBe(bytes.second)
    expect(bytes.first).not.toBe(source.bytes)
  })

  test('defines own __proto__ keys safely on objects and arrays', () => {
    for (const source of [{}, []]) {
      Object.defineProperty(source, '__proto__', {
        value: { polluted: true },
        enumerable: true,
      })
      const owned = cloneData(source)
      expect(Object.hasOwn(owned, '__proto__')).toBe(true)
      expect(Object.getOwnPropertyDescriptor(owned, '__proto__')?.value).toEqual({ polluted: true })
      expect(Object.getPrototypeOf(owned)).toBe(
        Array.isArray(source) ? Array.prototype : Object.prototype,
      )
      expect(Object.hasOwn(Object.prototype, 'polluted')).toBe(false)
    }
  })

  test('copies null-prototype records and ignores non-enumerable and symbol keys', () => {
    const source = Object.create(null)
    source.value = { optional: undefined }
    source[Symbol('ignored')] = () => 1
    Object.defineProperty(source, 'ignored', { value: () => 1 })
    const owned = cloneData(source)
    expect(Object.keys(owned)).toEqual(['value'])
    expect(owned.value).toEqual({ optional: undefined })
    expect(owned.value).not.toBe(source.value)
    expect(Object.getOwnPropertySymbols(owned)).toEqual([])
  })

  test('rejects uncloneable values with TypeError even when nested in a collection', () => {
    for (const value of [
      () => 1,
      Symbol('uncloneable'),
      new WeakMap(),
      new WeakSet(),
      Promise.resolve(1),
    ]) {
      expect(() => cloneData(value)).toThrow(TypeError)
      expect(() => cloneData({ value })).toThrow(TypeError)
      expect(() => cloneData(new Map([['key', value]]))).toThrow(TypeError)
      expect(() => cloneData(new Set([value]))).toThrow(TypeError)
    }
  })
})
