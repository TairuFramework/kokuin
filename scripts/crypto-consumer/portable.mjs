import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { existsSync } from 'node:fs'
import { nobleCrypto } from '@kokuin/crypto'

const seed = new Uint8Array(
  Buffer.from('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60', 'hex'),
)
const signature = await nobleCrypto.sign('EdDSA', seed, new Uint8Array())
assert.equal(
  Buffer.from(signature).toString('hex'),
  'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b',
)
assert.equal(
  Buffer.from(await nobleCrypto.blake3(new Uint8Array(), 16)).toString('hex'),
  'af1349b9f5f9a1a6a0404dea36dcc949',
)
assert.equal(
  existsSync(new URL('./node_modules/react-native-nitro-modules', import.meta.url)),
  false,
)
assert.equal(spawnSync('cargo', ['--version']).error?.code, 'ENOENT')
console.log('Packed portable crypto: OK; Nitro and Cargo absent')
