/** Own mutable data while preserving opaque runtime objects and callbacks. */
export function snapshotData<Value>(value: Value): Value {
  if (
    ArrayBuffer.isView(value) &&
    Object.prototype.toString.call(value) === '[object Uint8Array]'
  ) {
    return new Uint8Array(value.buffer, value.byteOffset, value.byteLength).slice() as Value
  }
  if (Array.isArray(value)) return value.map(snapshotData) as Value
  if (
    value !== null &&
    typeof value === 'object' &&
    (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null)
  ) {
    return Object.fromEntries(
      Object.entries(value).map(([key, child]) => [key, snapshotData(child)]),
    ) as Value
  }
  return value
}

export function snapshotCall<Value extends { transportContext?: unknown }>(value: Value): Value {
  const { transportContext, ...data } = value
  return {
    ...snapshotData(data),
    ...(Object.hasOwn(value, 'transportContext') ? { transportContext } : {}),
  } as Value
}
