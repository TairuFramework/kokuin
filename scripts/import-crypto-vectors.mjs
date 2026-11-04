// Regenerates packages/crypto-conformance/vectors/external.json from pinned upstream files.
//
//   node scripts/import-crypto-vectors.mjs <wycheproof checkout> <pyca/cryptography checkout> <BLAKE3 checkout>
//
// Each source file must match its recorded SHA-256, so a different upstream revision fails loudly
// instead of silently changing the expected outcomes.
//
// Expected outcomes come from the upstream verdicts plus this project's documented verification
// policy, never from running a provider:
// - Wycheproof Ed25519: `valid` accepts; `invalid` rejects; `acceptable` (small-order and
//   mixed-order public keys) rejects, because the contract rejects every point outside the
//   prime-order subgroup.
// - Wycheproof ECDSA P-256 (P1363): `valid` accepts unless s > n / 2, which the contract rejects as
//   malleable; `invalid` rejects. Every vector also runs with its key in compressed SEC1 form.
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { readFileSync, writeFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const [wycheproof, pyca, blake3] = process.argv.slice(2)
assert.ok(
  wycheproof && pyca && blake3,
  'usage: import-crypto-vectors.mjs <wycheproof> <pyca> <blake3>',
)

const SOURCES = {
  'wycheproof-ed25519': {
    repository: 'https://github.com/C2SP/wycheproof',
    commit: 'd17cc89fa5c8f4f4d378b5385ebf75da5d0926c9',
    file: 'testvectors_v1/ed25519_test.json',
    sha256: 'ea80ffebac085e21cb9d3e903e7fa2b448d96702da5b31f061d0b83b430b74b3',
    license: 'Apache-2.0',
    root: wycheproof,
  },
  'wycheproof-ecdsa-p256': {
    repository: 'https://github.com/C2SP/wycheproof',
    commit: 'd17cc89fa5c8f4f4d378b5385ebf75da5d0926c9',
    file: 'testvectors_v1/ecdsa_secp256r1_sha256_p1363_test.json',
    sha256: 'c60de693930e386c3a5472d08081623ef8504decc54b38ac01ec6b2a2575c986',
    license: 'Apache-2.0',
    root: wycheproof,
  },
  'supercop-ed25519': {
    repository: 'https://github.com/pyca/cryptography',
    commit: '1c141e91050ed8b361148536f25e929a360c9164',
    file: 'vectors/cryptography_vectors/asymmetric/Ed25519/sign.input',
    sha256: '8db1fea94f4e78958aac6e839b483cdd79096d1fe478285f15164f9e58361baf',
    license: 'Apache-2.0 OR BSD-3-Clause',
    note: 'SUPERCOP ed25519 sign.input. Entries 0-2 are RFC 8032 section 7.1 TEST 1-3.',
    root: pyca,
  },
  'blake3-official': {
    repository: 'https://github.com/BLAKE3-team/BLAKE3',
    commit: 'f55849f89cd85083c1c9daa2c5de20766f309c00',
    file: 'test_vectors/test_vectors.json',
    sha256: 'dcb91ea8accc77e6d6e632af7cdc1a99a9f3ae78cf648da595c7d064db32f624',
    license: 'CC0-1.0 OR Apache-2.0 OR Apache-2.0 WITH LLVM-exception',
    root: blake3,
  },
}

function read(id) {
  const source = SOURCES[id]
  const bytes = readFileSync(join(source.root, source.file))
  const digest = createHash('sha256').update(bytes).digest('hex')
  assert.equal(digest, source.sha256, `${id}: upstream file changed`)
  return bytes.toString('utf8')
}

const P256_N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n

function compressed(uncompressed) {
  assert.equal(uncompressed.length, 130)
  assert.equal(uncompressed.slice(0, 2), '04')
  const y = BigInt(`0x${uncompressed.slice(66)}`)
  return `${y & 1n ? '03' : '02'}${uncompressed.slice(2, 66)}`
}

const verify = []

const ed = JSON.parse(read('wycheproof-ed25519'))
for (const group of ed.testGroups) {
  for (const test of group.tests) {
    verify.push({
      source: 'wycheproof-ed25519',
      id: `tc${test.tcId}`,
      alg: 'EdDSA',
      publicKey: group.publicKey.pk,
      message: test.msg,
      signature: test.sig,
      valid: test.result === 'valid',
      upstream: test.result,
      flags: test.flags,
    })
  }
}

let highS = 0
const ecdsa = JSON.parse(read('wycheproof-ecdsa-p256'))
for (const group of ecdsa.testGroups) {
  assert.equal(group.sha, 'SHA-256')
  const key = group.publicKey.uncompressed
  for (const test of group.tests) {
    const isHighS = test.sig.length === 128 && BigInt(`0x${test.sig.slice(64)}`) > P256_N >> 1n
    const valid = test.result === 'valid' && !isHighS
    if (test.result === 'valid' && isHighS) highS++
    for (const [form, publicKey] of [
      ['uncompressed', key],
      ['compressed', compressed(key)],
    ]) {
      verify.push({
        source: 'wycheproof-ecdsa-p256',
        id: `tc${test.tcId}/${form}`,
        alg: 'ES256',
        publicKey,
        message: test.msg,
        signature: test.sig,
        valid,
        upstream: test.result,
        flags: isHighS ? [...test.flags, 'HighS'] : test.flags,
      })
    }
  }
}

// SUPERCOP lines: seed||publicKey : publicKey : message : signature||message :
const sign = []
const lines = read('supercop-ed25519').trim().split('\n')
lines.forEach((line, index) => {
  if (!(index < 64 || index % 32 === 31)) return
  const [secret, publicKey, message, signed] = line.split(':')
  assert.equal(secret.slice(64), publicKey)
  assert.equal(signed.slice(128), message)
  const entry = {
    source: 'supercop-ed25519',
    id: index < 3 ? `line${index} (RFC 8032 TEST ${index + 1})` : `line${index}`,
    seed: secret.slice(0, 64),
    publicKey,
    message,
    signature: signed.slice(0, 128),
  }
  sign.push(entry)
  verify.push({
    source: 'supercop-ed25519',
    id: entry.id,
    alg: 'EdDSA',
    publicKey,
    message,
    signature: entry.signature,
    valid: true,
    upstream: 'valid',
    flags: [],
  })
})

const official = JSON.parse(read('blake3-official'))
const blake3Cases = official.cases.map((test) => ({
  source: 'blake3-official',
  id: `len${test.input_len}`,
  inputLength: test.input_len,
  hash: test.hash,
}))

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const out = {
  description:
    'Pinned upstream vectors, regenerated by scripts/import-crypto-vectors.mjs. Read by @kokuin/crypto-conformance and crates/kokuin-crypto/tests/external.rs. `valid` is the expected outcome under this project policy; `upstream` keeps the source verdict. blake3 inputs are `inputLength` bytes of the repeating sequence 0..250, and `hash` is the first 131 bytes of output.',
  sources: Object.fromEntries(
    Object.entries(SOURCES).map(([id, { root: _root, ...source }]) => [id, source]),
  ),
  ed25519Sign: sign,
  verify,
  blake3: blake3Cases,
}
const target = join(root, 'packages/crypto-conformance/vectors/external.json')
writeFileSync(target, `${JSON.stringify(out, null, 2)}\n`)
// Leave the file exactly as the repository's formatter would, so `pnpm lint` never rewrites it.
execFileSync(join(root, 'node_modules/.bin/biome'), ['format', '--write', target], {
  stdio: 'ignore',
})
console.log(
  JSON.stringify({
    sign: sign.length,
    verify: verify.length,
    verifyValid: verify.filter((entry) => entry.valid).length,
    wycheproofValidHighS: highS,
    blake3: blake3Cases.length,
  }),
)
