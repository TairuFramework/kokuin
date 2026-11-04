# Controller async migration report

**Status:** DONE_WITH_CONCERNS

**Scope:** PR 2 of `2026-11-04-crypto-provider-integration.md`, building on the supplied `b0999db` baseline.

## Interface pre-flight

| Producer and consumer | Finding |
| --- | --- |
| Token provider options and controller | Existing exported `CryptoOptions` matches the six-method asynchronous provider contract. Reused it. |
| Controller and controller-conformance | Seven implementation members require Promises, including epoch construction. The suite remains independent of controller imports. |
| Controller and store-controller | The existing Promise-returning merge callback supports the new controller contract. No store API change is necessary. |
| Controller and workspace fixtures | Controller, capability, store-delegation, store-controller and integration helpers require awaited construction and folds. |

No conflict with the recorded design decisions blocked implementation. Native route selection remains deferred. All default operations use noble.

## Checklist completion

| Plan checklist item | Implementation and evidence |
| --- | --- |
| Provider-counter, operational-failure and fold-memo tests first | Added `packages/controller/test/provider-routing.test.ts` before production changes. Initial run: seven failures and one passing synchronous-enumeration test. |
| Ordered signing and bounded verification batches | `signEvent` uses `signBatch`. `verifySignatures` parses inputs before sequential `verifyBatch` calls, with at most 16 items each. Tests verify raw canonical messages, key order, signatures and batch sizes. |
| Parsing catches outside provider awaits | Key/signature decoding retains refusal catches. Provider operations execute outside those catches. Sentinel errors escape signature verification, folds and resolver history merges unchanged. |
| Causal evaluation order | Chain steps, epoch candidates and distinct signature copies await sequentially. No speculative verification crosses candidate boundaries. |
| Failed-signature accounting | Existing whole-copy charging and exhaustion checks remain intact. The provider-counter regression observes exactly 65 failing epoch checks after inception, in ascending ready-digest order. Existing request-budget and hostile-presentation suites pass. |
| Preserve limits | `MAX_EVENT_SIGNATURES = 16` and `MAX_FAILED_SIGNATURES = 64` remain unchanged. Root-chain sets larger than 16 retain acceptance through bounded chunks. The epoch shape limit still rejects oversized sets. |
| Forward every controller site | Updated events, epoch construction/authentication, chain/epoch folds, branch resolution, authoritative history, log helpers, current state, both identity constructors, keystore identity provisioning and resolver construction. |
| Synchronous profile enumeration | Replaced throwaway inception signing with `didFor`. A test makes all six noble-provider methods throw and verifies enumeration still returns synchronously without invoking them. |
| Unsigned reset inception derivation | Reset construction now derives the inception body without signing it. The provider-counter test proves one reset adds only its recovery signature batch. |
| Provider-partitioned fold memo | Weak provider identity tokens join the existing content key. One aggregate 256-entry LRU remains. Explicit noble and omitted selection resolve to the same provider. Lowered limits bypass the memo. Only settled successes enter it. |
| Await authoritative results | History and resolver paths await folds before reading results or writing memo entries. Provider refusals and exceptions leave history untouched. |
| Preserve resolver behaviour | Existing in-flight sharing, `finally` eviction, failed frozen-view retries and unchanged-log identity tests pass. Resolver construction captures provider, loader and history references. Unchanged branch winners also retain their original references. |
| Async conformance contract | Converted inception, rotate, reset, fold, branch resolution, epoch creation and test signing to Promise-returning contracts. Awaited local construction/fold/summary helpers. No controller import was added. |
| Workspace callers and fixtures | Updated every discovered caller in controller tests, capability tests, store-delegation tests, shared store-controller cases and integration fixtures. Async array builders use `Promise.all`; rejection and totality assertions await completion. |
| Synchronous enumeration regression | Included in the 19-test provider regression file and the existing profile suite. |

The repository-wide symbol search included internal helpers, device builders, fixtures, integration tests and aliased imports.
The complete build/type run verifies all 69 workspace tasks. No synchronous compatibility shim or subpath export was introduced.

## Additional security fix from final review

The fresh-context review found one Important issue: event mutation during suspended verification could install unauthenticated state.
The same race could cache the altered result under the original log digest.

Added delayed-provider regressions for inception keys, rotate snapshots, epoch revokes, authoritative persistence, memo reuse, branch winners and private identity material.
The first mutation run failed two tests. The corrected memo assertion was independently rerun with snapshot protection removed and failed on the substituted key.
The final implementation passes all these regressions.

`log-snapshot.ts` owns canonical event bodies and signature arrays before suspension.
Malformed bodies retain refusal behaviour without recursively cloning hostile deep input.
Memo keys, verified state and persisted authoritative logs describe the same snapshot.
Builders copy supplied snapshots, and identity construction copies private material before awaiting verification.
Original seen-log and branch references are returned only when their content still matches the authenticated snapshot.

Stored epoch authentication remains trusted under the existing LogStore contract.
This migration adds no durable provenance, historical rescan or provider-switch reauthentication of trusted stored epoch copies.

## Red-to-green evidence

All pnpm commands below used `PNPM_CONFIG_VERIFY_DEPS_BEFORE_RUN=false`.

| Check | Red result | Final result |
| --- | --- | --- |
| Initial provider regressions | `7 failed, 1 passed`, before production edits. Missing batches, ignored provider refusal and cross-provider memo acceptance were observed. | All provider regressions pass. |
| Root verification chunking | A 17-key set returned false instead of verifying in batches of 16 and 1. `1 failed, 8 passed`. | Ordered `[16, 1]` batches pass. |
| Suspended-input ownership | Folded state and authoritative resolution reflected mutation. `2 failed, 15 passed`. | Original authenticated state and persisted bytes are retained. |
| Corrected memo mutation reproduction | Protection temporarily removed, then restored. `1 failed, 18 skipped`; the original-key assertion detected substitution. | Included in the passing final suite. |
| Branch and identity ownership | Mutated branch result and changed private material caused failures. `2 failed, 17 passed`. | Both ownership regressions pass. |

Focused command:

```sh
PNPM_CONFIG_VERIFY_DEPS_BEFORE_RUN=false pnpm --filter @kokuin/controller exec vitest run test/provider-routing.test.ts
```

The final full controller suite includes all 19 provider tests: **49 files, 812 tests passed**.

## Required verification

### Workspace build and type checks

```sh
PNPM_CONFIG_VERIFY_DEPS_BEFORE_RUN=false pnpm exec turbo run build:js build:types test:types --continue
```

Actual final output:

```text
Tasks:    69 successful, 69 total
Cached:   53 cached, 69 total
Time:     5.916s
```

Exit status: 0.

### Affected unit suites

```sh
PNPM_CONFIG_VERIFY_DEPS_BEFORE_RUN=false pnpm exec turbo run test:unit --continue --concurrency=2 --filter @kokuin/controller --filter @kokuin/controller-conformance --filter @kokuin/store-controller --filter @kokuin/records --filter @kokuin/vault --filter @kokuin/store-vault
```

Actual final results:

```text
@kokuin/controller:       812 passed
@kokuin/store-controller:  33 passed, 1 skipped
@kokuin/records:          300 passed
@kokuin/vault:            154 passed
@kokuin/store-vault:      263 passed
Tasks:                    15 successful, 15 total
Cached:                    9 cached, 15 total
Time:                     21.985s
```

Exit status: 0. Controller-conformance has no standalone `test:unit` script. Controller's suite executes its conformance contract.
The store-controller skip is the Postgres-only independent-writer case on SQLite.

### Controller integration coverage

```sh
PNPM_CONFIG_VERIFY_DEPS_BEFORE_RUN=false pnpm --filter integration-tests exec vitest run test/store-controller.test.ts test/legacy-names.test.ts test/concurrency.test.ts
```

Actual final output:

```text
Test Files  3 passed (3)
Tests       271 passed | 3 skipped (274)
Duration    15.12s
```

Exit status: 0. This covers SQLite, Postgres log round trips, custom physical names and concurrent writers.
The three skips are backend-specific cases. Postgres was available for this run.

### Biome

```sh
./node_modules/.bin/biome ci .
```

Actual final output before adding this report:

```text
Checked 596 files in 248ms. No fixes applied.
```

Exit status: 0. The report-inclusive check also passed: `Checked 597 files in 242ms. No fixes applied.`

## Broader unit sweep

The complete workspace unit command was also run:

```sh
PNPM_CONFIG_VERIFY_DEPS_BEFORE_RUN=false pnpm exec turbo run test:unit --continue --concurrency=2
```

Actual final output:

```text
Tasks:    44 successful, 45 total
Cached:   27 cached, 45 total
Time:     22.094s
Failed:   @kokuin/electron#test:unit
```

Exit status: 1. The only failures were the three Electron lock tests listed below.
Capability and store-delegation consumer suites passed. Node produced no lock failure in this run.
Ledger hardware tests remained skipped without a device.

## Release intents

Added minor intents matching the existing provider-intent format:

- `.changeset/controller-crypto-provider.md`
- `.changeset/controller-conformance-crypto-provider.md`

Controller-conformance remains private and listed in `versioning.ignore`. Its intent records the changed exported contract without authorising publication.
Store-controller's factory and callback API remain unchanged, so no additional public-API intent is necessary here.
No manifest versions were bumped. No release, publication or downstream edit was performed.

## Deviations and execution notes

- The final review required input-ownership protection beyond the explicit controller checklist. It closes a security regression caused by suspension.
- Root signature sets had no 16-key cap. Verification uses bounded chunks rather than introducing a new root-chain rejection rule.
- The user prohibited installation. The crypto dependency and lockfile importer were updated directly. A missing local workspace symlink was created for verification.
- An initial caller-update script matched unrelated async functions. Those edits were restored from committed-file snapshots before the scoped migration continued.
- Read-only baseline snapshots supported comparison and restoration. No git command, install or add command ran.
- Git-based skill scripts, commits, branch integration and plan cleanup were omitted under the user's explicit constraints.
- Early test-oracle corrections fixed the failed-signature constant import and replaced locale collation with code-unit ordering.
- Early mechanical passes exposed missing array awaits, rejection assertions, helper return types and promise-sharing assignments. These were corrected before final verification.
- No alternative architecture, native routing, synchronous noble shim, transaction change or database schema change was introduced.

## Review disposition and concerns

The fresh reviewer found one Important issue. Its input-mutation and memo-poisoning reproduction is fixed with failing-then-passing regressions.
The complete controller suite passed after the fix. No second review was requested.

**Deferred minor:** expand the new provider-counter budget test to mixed signature counts and duplicate signature-copy ordering.
Existing request-budget tests pass, and the sequential copy-ordering and whole-copy charging algorithm remain unchanged.

Physical workload retesting and expanded mobile conformance remain release qualifications under the recorded decisions.
No native route or production-readiness claim is made. The measured native route manifest remains a follow-on deliverable.

The outstanding environment failures are listed below. They were not modified or worked around.

### Environment failures

All three failures are in `packages/electron/test/lock.test.ts`, under `ElectronKeyStore lockPath`:

1. `provideAsync works with a lockPath set`
2. `concurrent provideAsync calls converge on one key`
3. `no lockfile is left behind`

Shared error:

```text
SystemError: A system error occurred: uv_uptime returned EPERM (operation not permitted)
```

Electron result: `1 failed file, 2 passed files; 3 failed tests, 47 passed tests`.
These sandbox failures were reported without changing lock behaviour.

### Captured command-output files

The full command logs remain in the local temporary directory:

- `/tmp/kokuin-controller-red.log`
- `/tmp/kokuin-controller-batch-red.log`
- `/tmp/kokuin-controller-mutation-red.log`
- `/tmp/kokuin-controller-memo-mutation-red.log`
- `/tmp/kokuin-controller-ownership-red.log`
- `/tmp/kokuin-controller-review-unit.log`
- `/tmp/kokuin-controller-build-final.log`
- `/tmp/kokuin-controller-units-final.log`
- `/tmp/kokuin-controller-integration-final.log`
- `/tmp/kokuin-controller-all-units-final.log`
- `/tmp/kokuin-controller-biome-report.log`

Required checks pass. The broader sweep's environment failures and the deferred coverage minor account for DONE_WITH_CONCERNS.

## Performance fixes

Added a module-level, insertion-order cache for strict Ed25519 public-key validation.
It stores both acceptance and refusal under exact byte-derived hex keys, with a maximum of 256 entries.
Public-key validation retains decoding, small-order refusal and torsion-free validation. Every signature R point still receives strict validation without caching.
The patch intent is `.changeset/crypto-point-validation-cache.md`.

Controller signature verification now uses ordered chunks of four and stops after the first failing chunk.
Parsing catches remain outside provider awaits. The signature limit of 16 and whole-copy failed-signature charging remain unchanged.
Provider routing covers a 17-key set as `[4, 4, 4, 4, 1]`.
For 16 signatures, the first invalid signature causes one four-item call. All-valid input causes four four-item calls.

### Red then green

The cache tests initially produced `3 failed, 1 passed` against the uncached implementation.
They observed repeated key decoding, repeated subgroup validation and missing bounded eviction.
Noble freezes its methods, so a test-only module wrapper counts real decoding and subgroup operations.
The final cache tests compare uncached and cached valid, small-order and mixed-order keys, preserve R checks, verify eviction and mutate an offset input view.
The focused crypto run passed: `2 files, 9 tests`.

The routing tests initially produced `3 failed, 18 passed`.
They received `[16, 1]` instead of `[4, 4, 4, 4, 1]`, and `[16]` instead of the expected four-item chunks.
The full passing controller run includes all 21 provider routing tests and the unchanged request-budget assertions.
Crypto-conformance includes the strict provider contract and weakened-verifier self-tests, including subgroup-a and subgroup-r coverage.

### Before and after timings

All pnpm and Turbo commands used `PNPM_CONFIG_VERIFY_DEPS_BEFORE_RUN=false`. No git, install or add command ran.
Measurements used the same four-file command from `packages/controller`:

```sh
PNPM_CONFIG_VERIFY_DEPS_BEFORE_RUN=false pnpm exec vitest run test/request-budget.test.ts test/atk-supersede-length.test.ts test/epoch-heads.test.ts test/epoch-fold.test.ts --reporter=verbose
```

The control temporarily removed both production fixes and rebuilt crypto JavaScript. Filesystem snapshots preserved the fixed code.
Both fixes were restored and crypto rebuilt before the after measurement.
Earlier measurements using existing generated libraries were excluded because the workspace rebuild materially changed timings.
File rows sum reported test-body durations, excluding import and setup time. Files execute concurrently within each command.

| Workload | Rebuilt before | Rebuilt after |
| --- | ---: | ---: |
| request-budget, 10 tests | 7.239s | 2.320s |
| atk-supersede-length, 4 tests | 4.338s | 1.906s |
| epoch-heads, 8 tests | 3.142s | 1.416s |
| 150-seed epoch-fold property | 12.463s | 13.031s |
| Four-file command, 53 tests | 30.75s | 21.08s |

The property remains expensive and shows no measured improvement in this comparison.
These are single-run wall-clock observations, not statistically controlled benchmarks.

### Isolated durations and timeouts

The exact controller-alone command initially passed `49 files, 814 tests` in `21.08s`.
A subsequent verbose run overlapping the workspace build timed out the property at 30 seconds and the provider budget counter at five seconds.
The first affected-unit run also timed out only the property: `813 passed, 1 failed`, with the other affected suites passing.
These failures prompted isolated measurements before changing timeouts.

| Test | Isolated duration | Explicit timeout |
| --- | ---: | ---: |
| `epoch-fold`: no seed throws, and every shuffle of a seed folds to the same head | 28.866s | 90s, previously 30s |
| `members`: a delayed renew or remove of an old add does not touch a re-add of the same key | 2.794s | 9s, previously 30s |
| `provider-routing`: hostile epoch candidates stop at the failed signature budget in causal order | 1.873s | Default 5s retained |

The isolated property command selected only that test. The other isolated command selected the permutation and counter tests in their respective files.
The permutation checks all 120 presentation orders. Both explicit timeouts apply only to expensive property tests, with approximately threefold headroom.
No blanket timeout configuration changed.

### Verification output

The requested affected-unit command initially stopped before running tasks:

```text
x No package found with name '@kokuin/crypto-node' in workspace
```

The workspace contains `@kokuin/crypto` and `@kokuin/crypto-native`, but no `@kokuin/crypto-node`.
Verification therefore reruns the remaining requested packages without inventing a substitute package.
Controller-conformance has no standalone unit script. Controller's conformance tests execute its contract.

Full command logs remain under `/tmp/kokuin-perf-*.log`, including red tests, rebuilt comparisons, isolated tests and verification runs.

Final controller-alone command:

```sh
cd packages/controller
PNPM_CONFIG_VERIFY_DEPS_BEFORE_RUN=false pnpm exec vitest run
```

```text
Test Files  49 passed (49)
Tests       814 passed (814)
Duration    25.29s
```

Exit status: 0.

Final root build and type command:

```sh
PNPM_CONFIG_VERIFY_DEPS_BEFORE_RUN=false pnpm exec turbo run build:js build:types test:types --continue
```

```text
Tasks:    69 successful, 69 total
Cached:   26 cached, 69 total
Time:     24.578s
```

Exit status: 0. Turbo emitted sandbox cache IO warnings (`Operation not permitted`), without failing tasks.

Final affected-unit command, excluding only the absent package:

```sh
PNPM_CONFIG_VERIFY_DEPS_BEFORE_RUN=false pnpm exec turbo run test:unit --continue --concurrency=2 --filter @kokuin/crypto --filter @kokuin/crypto-conformance --filter @kokuin/controller --filter @kokuin/controller-conformance --filter @kokuin/store-controller --filter @kokuin/records
```

```text
@kokuin/crypto:            9 passed
@kokuin/crypto-conformance: 11 passed
@kokuin/controller:       814 passed
@kokuin/store-controller: 33 passed, 1 skipped
@kokuin/records:          300 passed
Tasks:                   14 successful, 14 total
Cached:                  7 cached, 14 total
Time:                    35.817s
```

Exit status: 0. Total: 1,167 passed, one skipped. The skip remains the Postgres-only independent-writer case on SQLite.
The final controller property took 13.681s. The permutation test took 6.193s within the complete affected-unit run.
Crypto-conformance's 11 passing tests include the weakened-verifier self-tests.

Final formatting and lint command:

```sh
./node_modules/.bin/biome ci .
```

```text
Checked 598 files. No fixes applied.
```

Exit status: 0, including this report.

**Performance-fix status:** DONE_WITH_CONCERNS. Both regressions have red-then-green coverage, and all available requested checks pass.
The requested crypto-node unit suite cannot run because that package is absent. The property remains expensive and timings vary with contention.
No native-provider qualification or new resolution of the earlier Electron environment failures is claimed.
