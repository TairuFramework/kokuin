/**
 * Own controller data without a host clone API. Event bodies are canonicalizable records; folded
 * states also contain Maps and Sets. Preserve shared references (including skipped chain states)
 * within each copy. Other object types are outside this internal data contract.
 */
export function cloneData<TData>(value: TData): TData {
  const seen = new Map<object, unknown>()

  function clone(value: unknown): unknown {
    if (typeof value === 'function' || typeof value === 'symbol') {
      throw new TypeError('Cannot clone controller data')
    }
    if (value === null || typeof value !== 'object') return value
    if (seen.has(value)) return seen.get(value)

    // Tag check, not instanceof: bytes may come from another realm.
    if (Object.prototype.toString.call(value) === '[object Uint8Array]') {
      const copy = new Uint8Array(value as Uint8Array)
      seen.set(value, copy)
      return copy
    }
    if (value instanceof Map) {
      const copy = new Map<unknown, unknown>()
      seen.set(value, copy)
      for (const [key, entry] of value) copy.set(clone(key), clone(entry))
      return copy
    }
    if (value instanceof Set) {
      const copy = new Set<unknown>()
      seen.set(value, copy)
      for (const entry of value) copy.add(clone(entry))
      return copy
    }

    const array = Array.isArray(value)
    const prototype = Object.getPrototypeOf(value)
    if (!array && prototype !== Object.prototype && prototype !== null) {
      throw new TypeError('Cannot clone controller data')
    }
    const copy = array ? new Array<unknown>(value.length) : {}
    seen.set(value, copy)
    for (const key of Object.keys(value)) {
      // Assignment would invoke Object.prototype.__proto__ instead of retaining an own data key.
      Object.defineProperty(copy, key, {
        value: clone((value as Record<string, unknown>)[key]),
        enumerable: true,
        configurable: true,
        writable: true,
      })
    }
    return copy
  }

  return clone(value) as TData
}
