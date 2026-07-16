/**
 * The persisted keyID → encrypted-key map.
 *
 * `getKeys` MUST return a **null-prototype** object. A plain `{}` inherits from
 * `Object.prototype`, so `keys['constructor']` reads back a function rather than `undefined`,
 * and `keys['__proto__'] = value` sets the prototype instead of creating an own property —
 * silently discarding the key. With a null prototype both behave as ordinary string keys.
 */
export type KeyStorage = {
  getKeys: () => Record<string, string>
  setKeys: (keys: Record<string, string>) => void
}
