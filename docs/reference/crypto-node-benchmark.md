# Node crypto benchmark gate

`scripts/bench-crypto-node.mjs` times `@kokuin/crypto-napi` against `@kokuin/crypto-node`, its fallback, with strict noble as context.
It decides whether each native route pays off. `.github/workflows/crypto-node-gate.yml` runs it on `ubuntu-latest` (x86_64) and `ubuntu-24.04-arm` (arm64).
That happens on manual dispatch and on pull requests that touch the Rust crates or the Node crypto packages.
Each job uploads its JSON report and writes a summary table to the run.

```sh
pnpm --filter @kokuin/crypto-napi... build
pnpm --filter @kokuin/crypto-napi run build:native
node scripts/bench-crypto-node.mjs --runs 5 --out report.json
```

## Matrix

The matrix follows call shapes measured on the provider-integration branch: the token, capability, controller and store-delegation suites (13,809 calls), then the records, vault and store-vault suites (69,678 calls).

- Controller `verifyBatch` is nearly always one item and at most 4.
- Signing batches reach 17, a reset or rotate signing set.
- Signed messages run from about 140 B to 2.5 KiB (records and vault), and capability chains reach about 12 KiB.
- blake3 is only ever a single call so far. Records and vault hash 36 B into 16-byte digests, and about 1–2.6 KiB into 32-byte digests.
  store-vault alone made about 60,000 single calls across the record, vault and store-vault suites (69,678 calls).

| Dimension | Values |
| --- | --- |
| Operations | Ed25519 sign, Ed25519 verify, ES256 verify, blake3 |
| Modes | Single call; batches of 1, 4 and 17 |
| Message sizes | 256 B, 1 KiB, 2.5 KiB and 12 KiB for signatures |
| blake3 inputs | 36 B into 16 bytes; 1 KiB, 2.6 KiB and 64 KiB into 32 bytes |

No `blake3Batch` traffic exists yet. If store-vault's single calls become batches, their record page and chunk sizes join the matrix.

Each cell runs five times, rotating provider order between runs. Each measurement warms up first.
It then takes 30 to 20,000 samples within a fixed time budget. Strict noble runs once per cell, as context.

## Rule

A run passes when `crypto-napi`'s median is at least 10% below `nodeCrypto`'s.
Its p95 may be at most 10% above `nodeCrypto`'s, plus 20 µs.
A cell passes when at least four of five runs pass and the median across runs passes too.
ES256 cells are reported as `delegated`, because `crypto-napi` sends ES256 to `nodeCrypto`. The job fails when any gated cell fails.

The tolerances differ from the [mobile gate](../agents/plans/next/2026-10-27-crypto-benchmark-gate.md), which requires p95 to be no worse in every run.
That gate runs on idle physical phones. Shared CI runners add garbage-collection pauses and timer noise to tails, and occasional outlier runs.
Without the tolerances, cells with a stable 30% median win failed on single-run tail spikes.
A 36-byte blake3 call with a 2× better median and mean also failed on occasional 15 µs runtime pauses.
A tail under 20 µs is far below any event-loop responsiveness concern.

## Routes the gate set

The first local runs found two routes slower than the fallback, and three routes where the pool cost more than it saved.
The provider now routes:

| Call | Route |
| --- | --- |
| Ed25519 sign, Ed25519 verify, blake3 single calls | Native, calling thread |
| ES256 verify, single and batched | `nodeCrypto`. Native batches were about 3× slower, at about 360 µs per item against 107 µs. |
| Ed25519 verify batch of one | Native, calling thread. The pool hop made it 142 µs against 98 µs. |
| Ed25519 verify batch of two or more | Native, libuv pool, keeping about 100 µs per item off the event loop |
| Ed25519 sign batch of up to 32 | Native, calling thread. The pool was slower for every size measured. |
| Ed25519 sign batch above 32 | Native, libuv pool |
| blake3 batch up to 1 MiB of input | Native, calling thread. 1 MiB hashes in about 135 µs, and the pool was always slower. |
| blake3 batch above 1 MiB | Native, libuv pool |

## Local results

One run of the full gate in a shared 4-vCPU x86_64 container (Intel Xeon), Node 22.23.4: proceed, 64 of 64 cells.
Values are medians across five runs, in µs. CI results for x86_64 and arm64 are attached to each workflow run.

| Operation | Mode | Bytes | crypto-napi | nodeCrypto | strict noble | Status |
| --- | --- | --- | --- | --- | --- | --- |
| ed25519-sign | single | 256 | 26.9 | 60.3 | 459.3 | pass |
| ed25519-verify | single | 256 | 97.0 | 2445.5 | 2491.9 | pass |
| es256-verify | single | 256 | 111.0 | 111.6 | 1866.6 | delegated |
| ed25519-sign | single | 1024 | 29.4 | 62.2 | 499.4 | pass |
| ed25519-verify | single | 1024 | 98.0 | 2435.3 | 2435.6 | pass |
| es256-verify | single | 1024 | 110.9 | 108.7 | 1673.3 | delegated |
| ed25519-sign | single | 2560 | 34.0 | 66.8 | 469.5 | pass |
| ed25519-verify | single | 2560 | 100.7 | 2434.8 | 2435.7 | pass |
| es256-verify | single | 2560 | 110.2 | 109.7 | 1664.0 | delegated |
| ed25519-sign | single | 12288 | 62.3 | 89.5 | 640.2 | pass |
| ed25519-verify | single | 12288 | 115.6 | 2573.6 | 2543.9 | pass |
| es256-verify | single | 12288 | 118.5 | 117.1 | 1726.2 | delegated |
| blake3/16 | single | 36 | 0.9 | 2.2 | 2.4 | pass |
| blake3/32 | single | 1024 | 1.7 | 14.2 | 14.2 | pass |
| blake3/32 | single | 2600 | 2.2 | 36.3 | 36.9 | pass |
| blake3/32 | single | 65536 | 9.3 | 915.0 | 925.3 | pass |
| ed25519-sign | batch of 1 | 256 | 27.1 | 61.1 | 427.4 | pass |
| ed25519-verify | batch of 1 | 256 | 98.0 | 2435.4 | 2416.0 | pass |
| es256-verify | batch of 1 | 256 | 114.6 | 113.9 | 1713.8 | delegated |
| ed25519-sign | batch of 1 | 1024 | 29.5 | 62.3 | 440.5 | pass |
| ed25519-verify | batch of 1 | 1024 | 100.8 | 2449.7 | 2423.4 | pass |
| es256-verify | batch of 1 | 1024 | 116.5 | 115.5 | 1671.6 | delegated |
| ed25519-sign | batch of 1 | 2560 | 34.0 | 66.6 | 477.6 | pass |
| ed25519-verify | batch of 1 | 2560 | 103.4 | 2448.7 | 2463.8 | pass |
| es256-verify | batch of 1 | 2560 | 119.1 | 118.4 | 1665.8 | delegated |
| ed25519-sign | batch of 1 | 12288 | 62.5 | 89.5 | 651.8 | pass |
| ed25519-verify | batch of 1 | 12288 | 118.3 | 2558.4 | 2541.6 | pass |
| es256-verify | batch of 1 | 12288 | 125.0 | 124.4 | 1755.5 | delegated |
| blake3/16 | batch of 1 | 36 | 1.4 | 2.4 | 2.5 | pass |
| blake3/32 | batch of 1 | 1024 | 1.9 | 14.2 | 14.3 | pass |
| blake3/32 | batch of 1 | 2600 | 2.3 | 36.1 | 36.8 | pass |
| blake3/32 | batch of 1 | 65536 | 9.4 | 899.1 | 985.8 | pass |
| ed25519-sign | batch of 4 | 256 | 108.9 | 266.7 | 1742.0 | pass |
| ed25519-verify | batch of 4 | 256 | 449.7 | 9835.8 | 9901.2 | pass |
| es256-verify | batch of 4 | 256 | 439.1 | 438.1 | 6780.1 | delegated |
| ed25519-sign | batch of 4 | 1024 | 117.9 | 247.3 | 1861.3 | pass |
| ed25519-verify | batch of 4 | 1024 | 458.8 | 9960.1 | 9952.4 | pass |
| es256-verify | batch of 4 | 1024 | 446.2 | 434.3 | 6859.4 | delegated |
| ed25519-sign | batch of 4 | 2560 | 135.4 | 262.0 | 2012.7 | pass |
| ed25519-verify | batch of 4 | 2560 | 462.5 | 9838.5 | 9739.3 | pass |
| es256-verify | batch of 4 | 2560 | 443.9 | 434.4 | 6549.3 | delegated |
| ed25519-sign | batch of 4 | 12288 | 250.1 | 356.2 | 2650.7 | pass |
| ed25519-verify | batch of 4 | 12288 | 533.0 | 10268.7 | 10235.2 | pass |
| es256-verify | batch of 4 | 12288 | 464.1 | 453.4 | 6808.0 | delegated |
| blake3/16 | batch of 4 | 36 | 3.9 | 9.9 | 10.1 | pass |
| blake3/32 | batch of 4 | 1024 | 7.4 | 58.1 | 58.5 | pass |
| blake3/32 | batch of 4 | 2600 | 9.9 | 145.0 | 145.3 | pass |
| blake3/32 | batch of 4 | 65536 | 38.2 | 3738.7 | 3726.9 | pass |
| ed25519-sign | batch of 17 | 256 | 463.2 | 1031.2 | 7415.8 | pass |
| ed25519-verify | batch of 17 | 256 | 1794.8 | 42057.3 | 42304.4 | pass |
| es256-verify | batch of 17 | 256 | 1875.7 | 1851.7 | 28662.5 | delegated |
| ed25519-sign | batch of 17 | 1024 | 497.9 | 1061.1 | 8835.2 | pass |
| ed25519-verify | batch of 17 | 1024 | 1809.2 | 41820.1 | 42016.2 | pass |
| es256-verify | batch of 17 | 1024 | 1890.9 | 1866.5 | 29156.8 | delegated |
| ed25519-sign | batch of 17 | 2560 | 578.0 | 1124.9 | 8433.1 | pass |
| ed25519-verify | batch of 17 | 2560 | 1858.2 | 41661.2 | 41873.6 | pass |
| es256-verify | batch of 17 | 2560 | 1903.7 | 1870.8 | 28582.3 | delegated |
| ed25519-sign | batch of 17 | 12288 | 1057.9 | 1517.9 | 11361.4 | pass |
| ed25519-verify | batch of 17 | 12288 | 2106.4 | 43318.1 | 43263.5 | pass |
| es256-verify | batch of 17 | 12288 | 1981.0 | 1945.0 | 29239.0 | delegated |
| blake3/16 | batch of 17 | 36 | 15.9 | 41.9 | 40.5 | pass |
| blake3/32 | batch of 17 | 1024 | 58.6 | 247.9 | 246.0 | pass |
| blake3/32 | batch of 17 | 2600 | 66.8 | 634.7 | 659.0 | pass |
| blake3/32 | batch of 17 | 65536 | 321.8 | 16118.2 | 16103.0 | pass |
