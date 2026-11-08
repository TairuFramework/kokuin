/** Accept byte views across realms while excluding shared and detached buffers. */
export function assertUnsharedBytes(value: Uint8Array): asserts value is Uint8Array<ArrayBuffer> {
  if (
    !ArrayBuffer.isView(value) ||
    Object.prototype.toString.call(value) !== '[object Uint8Array]' ||
    Object.prototype.toString.call(value.buffer) !== '[object ArrayBuffer]'
  ) {
    throw new TypeError('Expected an unshared Uint8Array')
  }
  // Throws TypeError on a detached buffer.
  new Uint8Array(value.buffer, value.byteOffset, value.byteLength)
}
