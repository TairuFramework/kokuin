import type { CryptoProvider } from '@kokuin/crypto'
import { cryptoConformance } from '@kokuin/crypto-conformance'
import { ed25519 } from '@noble/curves/ed25519.js'
import { p256 } from '@noble/curves/nist.js'
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js'

import { strictNoble } from './strict-noble'

function equal(actual: Uint8Array, expected: Uint8Array): void {
  if (bytesToHex(actual) !== bytesToHex(expected)) throw new Error('Crypto byte mismatch')
}

export async function checkNativeCrypto(native: CryptoProvider): Promise<void> {
  for (const entry of cryptoConformance(native)) await entry.run()
  const seed = hexToBytes('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60')
  const message = new Uint8Array()
  const key = ed25519.getPublicKey(seed)
  const expected = await strictNoble.sign('EdDSA', seed, message)
  const padded = new Uint8Array(40)
  padded.set(seed, 4)
  const pending = native.sign('EdDSA', padded.subarray(4, 36), message)
  padded.fill(0)
  const retained = await pending
  equal(retained, expected)
  const signatures = await native.signBatch('EdDSA', [
    { privateKey: seed, message },
    { privateKey: seed, message: new Uint8Array([1]) },
  ])
  equal(signatures[0] as Uint8Array, expected)
  equal(signatures[1] as Uint8Array, await strictNoble.sign('EdDSA', seed, new Uint8Array([1])))
  if (!(await native.verify('EdDSA', retained, message, key)))
    throw new Error('Valid Ed25519 signature rejected')
  const results = await native.verifyBatch([
    { alg: 'EdDSA', signature: retained, message, publicKey: key },
    { alg: 'EdDSA', signature: retained, message: new Uint8Array([1]), publicKey: key },
    { alg: 'EdDSA', signature: new Uint8Array(), message, publicKey: key },
  ])
  if (JSON.stringify(results) !== '[true,false,false]')
    throw new Error('Verification batch order mismatch')
  // Identity, mixed-order and other adversarial vectors run above through the shared corpus.
  const secret = new Uint8Array(32)
  secret[31] = 1
  const esKey = p256.getPublicKey(secret)
  const esSignature = p256.sign(message, secret, { lowS: true })
  if (!(await native.verify('ES256', esSignature, message, esKey)))
    throw new Error('Valid ES256 signature rejected')
  for (const length of [16, 32, 64]) {
    equal(await native.blake3(message, length), await strictNoble.blake3(message, length))
    const hashes = await native.blake3Batch([message, seed], length)
    equal(hashes[0] as Uint8Array, await strictNoble.blake3(message, length))
    equal(hashes[1] as Uint8Array, await strictNoble.blake3(seed, length))
  }
  if (
    (await native.signBatch('EdDSA', [])).length !== 0 ||
    (await native.verifyBatch([])).length !== 0 ||
    (await native.blake3Batch([], 32)).length !== 0
  )
    throw new Error('Empty batch mismatch')
  // Retained output must survive subsequent native allocations and Promise settlements.
  equal(retained, expected)
}
