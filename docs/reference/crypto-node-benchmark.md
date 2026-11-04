# Node crypto benchmark gate

`scripts/bench-crypto-node.mjs` times `@kokuin/crypto-napi` against `@kokuin/crypto-node`, its fallback, with strict noble as context.
It decides whether each native route pays off. `.github/workflows/crypto-node-gate.yml` runs it on `ubuntu-latest` (x86_64) and `ubuntu-24.04-arm` (arm64).
That happens on manual dispatch and on pull requests that touch the Rust crates or the Node crypto packages.
Each job uploads its JSON report and writes a summary table to the run.

```sh
pnpm --filter @kokuin/crypto-napi... build
node scripts/build-crypto-napi.mjs
node scripts/bench-crypto-node.mjs --runs 5 --out report.json
```

## Matrix

The matrix follows call shapes measured on the provider-integration branch, across the token, capability, controller and store-delegation suites (13,809 calls).

- Controller `verifyBatch` is nearly always one item and at most 4.
- Signing batches reach 17, a reset or rotate signing set.
- Signed messages run from about 140 B to 1 KiB, and capability chains reach about 12 KiB.

| Dimension | Values |
| --- | --- |
| Operations | Ed25519 sign, Ed25519 verify, ES256 verify, blake3 (32-byte output) |
| Modes | Single call; batches of 1, 4 and 17 |
| Message sizes | 256 B, 1 KiB and 12 KiB for signatures; 32 B, 1 KiB and 64 KiB for blake3 |

No record or vault blake3 traffic exists yet. Its shapes join the matrix once those packages use the provider.

Each cell runs five times, rotating provider order between runs. Each measurement warms up first.
It then takes 30 to 400 samples within a fixed time budget. Strict noble runs once per cell, as context.

## Rule

A run passes when `crypto-napi`'s median is at least 10% below `nodeCrypto`'s.
Its p95 may be at most 10% above `nodeCrypto`'s, plus 5 µs.
A cell passes when at least four of five runs pass and the median across runs passes too.
ES256 cells are reported as `delegated`, because `crypto-napi` sends ES256 to `nodeCrypto`. The job fails when any gated cell fails.

The tolerances differ from the [mobile gate](../agents/plans/next/2026-10-27-crypto-benchmark-gate.md), which requires p95 to be no worse in every run.
That gate runs on idle physical phones. Shared CI runners add garbage-collection pauses and timer noise to tails, and occasional outlier runs.
Without the tolerances, cells with a stable 30% median win failed on single-run tail spikes.

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

One run of the full gate in a shared 4-vCPU x86_64 container (Intel Xeon), Node 22.23.4: proceed, 48 of 48 cells.
Values are medians across five runs, in µs. CI results for x86_64 and arm64 are attached to each workflow run.

| Operation | Mode | Bytes | crypto-napi | nodeCrypto | strict noble | Status |
| --- | --- | --- | --- | --- | --- | --- |
| ed25519-sign | single | 256 | 27.0 | 61.8 | 440.7 | pass |
| ed25519-verify | single | 256 | 97.1 | 2423.3 | 2419.1 | pass |
| es256-verify | single | 256 | 107.6 | 106.8 | 1657.1 | delegated |
| ed25519-sign | single | 1024 | 29.2 | 61.5 | 444.0 | pass |
| ed25519-verify | single | 1024 | 98.4 | 2404.5 | 2400.7 | pass |
| es256-verify | single | 1024 | 106.9 | 109.6 | 1665.8 | delegated |
| ed25519-sign | single | 12288 | 60.5 | 88.9 | 656.6 | pass |
| ed25519-verify | single | 12288 | 115.6 | 2523.3 | 2495.0 | pass |
| es256-verify | single | 12288 | 112.8 | 113.1 | 1807.5 | delegated |
| blake3 | single | 32 | 1.1 | 2.9 | 2.5 | pass |
| blake3 | single | 1024 | 1.6 | 15.0 | 14.8 | pass |
| blake3 | single | 65536 | 9.3 | 1037.1 | 1023.9 | pass |
| ed25519-sign | batch of 1 | 256 | 26.9 | 60.1 | 425.9 | pass |
| ed25519-verify | batch of 1 | 256 | 98.7 | 2412.3 | 2398.7 | pass |
| es256-verify | batch of 1 | 256 | 114.6 | 112.4 | 1653.0 | delegated |
| ed25519-sign | batch of 1 | 1024 | 29.2 | 62.0 | 576.9 | pass |
| ed25519-verify | batch of 1 | 1024 | 99.3 | 2428.5 | 2431.9 | pass |
| es256-verify | batch of 1 | 1024 | 116.6 | 116.3 | 1647.0 | delegated |
| ed25519-sign | batch of 1 | 12288 | 61.2 | 89.5 | 695.6 | pass |
| ed25519-verify | batch of 1 | 12288 | 116.3 | 2549.8 | 2554.7 | pass |
| es256-verify | batch of 1 | 12288 | 120.0 | 121.8 | 1712.2 | delegated |
| blake3 | batch of 1 | 32 | 1.0 | 2.5 | 3.1 | pass |
| blake3 | batch of 1 | 1024 | 1.7 | 14.2 | 14.7 | pass |
| blake3 | batch of 1 | 65536 | 9.2 | 925.3 | 924.0 | pass |
| ed25519-sign | batch of 4 | 256 | 108.2 | 240.0 | 1733.7 | pass |
| ed25519-verify | batch of 4 | 256 | 446.3 | 9788.6 | 9793.6 | pass |
| es256-verify | batch of 4 | 256 | 432.5 | 425.7 | 6725.2 | delegated |
| ed25519-sign | batch of 4 | 1024 | 116.0 | 247.8 | 1844.9 | pass |
| ed25519-verify | batch of 4 | 1024 | 450.3 | 9844.7 | 10043.4 | pass |
| es256-verify | batch of 4 | 1024 | 436.5 | 426.3 | 6590.5 | delegated |
| ed25519-sign | batch of 4 | 12288 | 243.6 | 356.4 | 2639.8 | pass |
| ed25519-verify | batch of 4 | 12288 | 525.3 | 10276.5 | 10288.8 | pass |
| es256-verify | batch of 4 | 12288 | 450.3 | 448.5 | 6918.4 | delegated |
| blake3 | batch of 4 | 32 | 3.5 | 9.5 | 8.3 | pass |
| blake3 | batch of 4 | 1024 | 7.0 | 58.4 | 58.0 | pass |
| blake3 | batch of 4 | 65536 | 37.8 | 3918.4 | 3982.9 | pass |
| ed25519-sign | batch of 17 | 256 | 457.5 | 1024.1 | 7361.9 | pass |
| ed25519-verify | batch of 17 | 256 | 1779.8 | 41843.0 | 41315.3 | pass |
| es256-verify | batch of 17 | 256 | 1850.1 | 1834.6 | 28350.7 | delegated |
| ed25519-sign | batch of 17 | 1024 | 496.6 | 1061.9 | 8085.1 | pass |
| ed25519-verify | batch of 17 | 1024 | 1770.3 | 41753.8 | 41329.8 | pass |
| es256-verify | batch of 17 | 1024 | 1859.8 | 1844.6 | 28141.1 | delegated |
| ed25519-sign | batch of 17 | 12288 | 1040.6 | 1518.6 | 11343.0 | pass |
| ed25519-verify | batch of 17 | 12288 | 2094.2 | 43367.6 | 43475.9 | pass |
| es256-verify | batch of 17 | 12288 | 1946.3 | 1935.8 | 30105.7 | delegated |
| blake3 | batch of 17 | 32 | 16.1 | 41.5 | 37.6 | pass |
| blake3 | batch of 17 | 1024 | 29.1 | 262.6 | 267.0 | pass |
| blake3 | batch of 17 | 65536 | 333.2 | 17201.3 | 17626.3 | pass |
