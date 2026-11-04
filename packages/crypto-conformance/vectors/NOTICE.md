# Third-party test vectors

`external.json` is derived from the upstream files below by `scripts/import-crypto-vectors.mjs`,
which checks each file's SHA-256 before converting it. `corpus.json` is original to this project.

| Set | Source | Revision | Licence |
| --- | --- | --- | --- |
| `wycheproof-ed25519` | [C2SP/wycheproof](https://github.com/C2SP/wycheproof) `testvectors_v1/ed25519_test.json` | `d17cc89fa5c8f4f4d378b5385ebf75da5d0926c9` | Apache-2.0 |
| `wycheproof-ecdsa-p256` | [C2SP/wycheproof](https://github.com/C2SP/wycheproof) `testvectors_v1/ecdsa_secp256r1_sha256_p1363_test.json` | `d17cc89fa5c8f4f4d378b5385ebf75da5d0926c9` | Apache-2.0 |
| `supercop-ed25519` | SUPERCOP `sign.input`, as shipped in [pyca/cryptography](https://github.com/pyca/cryptography) `vectors/cryptography_vectors/asymmetric/Ed25519/sign.input` | `1c141e91050ed8b361148536f25e929a360c9164` | Apache-2.0 OR BSD-3-Clause |
| `blake3-official` | [BLAKE3-team/BLAKE3](https://github.com/BLAKE3-team/BLAKE3) `test_vectors/test_vectors.json` | `f55849f89cd85083c1c9daa2c5de20766f309c00` | CC0-1.0 OR Apache-2.0 OR Apache-2.0 WITH LLVM-exception |

Changes from upstream:

- Wycheproof Ed25519 `acceptable` vectors, which use small-order or mixed-order public keys, expect rejection.
- Wycheproof ECDSA `valid` vectors with s > n / 2 expect rejection and carry an added `HighS` flag.
- Every Wycheproof ECDSA vector also appears with its public key in compressed SEC1 form.
- `supercop-ed25519` keeps entries 0–63 and every 32nd entry after them (94 of 1,024), so message lengths reach 1,023 bytes without the full 2.4 MB file.
  Entries 0–2 are RFC 8032 section 7.1 TEST 1–3.
- blake3 keeps only the plain hash mode, truncated to its first 131 bytes.
