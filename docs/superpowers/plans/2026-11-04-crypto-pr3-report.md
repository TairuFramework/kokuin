# Crypto provider integration PR 3 report

Date: 2026-11-04.
Scope: records hashing, carried content digests, and mandatory vault/store-vault consumer updates.
Status: **DONE_WITH_CONCERNS**. All requested checks pass. The new dependency needs later lockfile synchronisation.

## Checklist implementation

| Plan checklist item | Implementation and evidence |
| --- | --- |
| Freeze golden digests and fingerprints | `records/test/crypto-fixture.ts` freezes the canonical nested Unicode claim and its content digest. Provider tests freeze payload, empty-payload, tombstone, op-framing, leaf and fingerprint outputs. Initial literals came from the unchanged implementation before production edits. Additional non-empty range literals came from the saved original source, transpiled without changing its algorithms. |
| Capture canonical claims before suspension | `recordClaimDigest` canonicalises synchronously. `signRecordOp` captures canonical bytes before entering the identity queue. Delayed-provider tests mutate nested metadata after invocation. |
| Decode verified claims into owned storage | Verification decodes canonical authenticated token bytes into fresh JSON storage. It computes `contentDigest` before returning or memoising an operation. |
| Preserve string-version substitution | Content hashing substitutes only string `meta.version` for the digest HLC. Literal fixtures cover string and numeric versions. Other claim fields retain their canonical bytes. |
| Carry digests through copies and fixtures | `VerifiedRecordOp` requires `contentDigest`. `copyOp`, memo entries, decision construction and hand-built fixtures retain it. Policy fixtures use an independent noble oracle. Malformed-policy fixtures mutate an initially valid fixture after digest construction. |
| Replace authenticated-claim comparisons | Decisions, policies, apply, visibility, vault branch selection and store-vault comparisons consume the carried field synchronously. |
| Isolate operation memos | One globally bounded 1024-entry LRU uses weak provider identities. Existing self-certifying issuer restrictions remain. Registries are captured before hashing. Scoped verifiers capture provider and method policy, share in-flight checks, and evict refusals/rejections. |
| Forward providers | Record op hashing, token verification, content hashing, payload checks, range helpers and requester reconciliation use the selected provider. Apply and visibility contexts carry it through dependencies and authorisation. |
| Snapshot payload views | `snapshotRecord` and payload hashing use `new Uint8Array(...)`, including Buffer subarrays. Apply owns its incoming records before verification. Visibility owns proof inputs and filtered output records. |
| Await payload authorisation boundaries | Apply awaits payload validation before hooks or persistence. Vault proof/record validation, decoding, store projections and coordinator checks await their previous checks. Existing transaction boundaries remain. |
| Preserve signer queues | Each identity queue now includes op hashing. A delayed hash cannot overlap the next hardware/prompting signing request. Rejections still release the queue. |
| Construct range ordering inputs honestly | `orderOf` accepts only the claim/opHash fields it reads. No fake content digest was added to its local input. |
| Preserve synchronous comparison APIs | Policy, decision, visibility-content and branch comparisons remain synchronous. `beginRecordPull` and range ordering remain synchronous. |
| Update all consumers | Repo-wide symbol searches covered source, tests, fixtures and integration case libraries. Every build/type task passes. Integration imports reuse the updated store-vault case libraries. |
| Special stored-metadata comparison | `records-rows.ts` awaits the altered metadata claim digest and compares it with authenticated `op.contentDigest`. Untouched claims in rows and adapters use the carried field. |
| Verify tombstones, convergence and rollback | Existing convergence/tombstone suites pass. New tests cover owned and ambient transaction rollback on payload-provider rejection, including a prior draft write and no clock advancement. |

## API and package changes

Records adds provider options after existing positional method-registry parameters.
Claim/payload digests, payload matching, range helpers and requester reconciliation now return Promises.
`VerifiedRecordOp.contentDigest` is required. Record verifier factories remain synchronous.
`ApplyRecordChunkParams`, receive contexts and visibility contexts carry provider selection.

Vault decoding now returns `Promise<DecodedVaultRecord>`.
Vault metadata validation and vault-owned BLAKE3 helpers retain their existing contracts for PR 4.
Vault branch selection reads carried digests and remains synchronous.
Store-vault factories retain their signatures while their internal consumers await records and decoding.

Added minor intents:

- `.changeset/records-crypto-provider.md`
- `.changeset/vault-crypto-provider.md`
- `.changeset/store-vault-crypto-provider.md`

Added dependency: `packages/records/package.json` declares `@kokuin/crypto: workspace:^`.
No other dependency was added. The lockfile was not edited.
The existing root workspace link resolved crypto for verification.
No symlink, install/add command, git command, version bump, publication or downstream edit was performed.

## Red-then-green evidence

Every pnpm invocation used `PNPM_CONFIG_VERIFY_DEPS_BEFORE_RUN=false`.
Focused regressions ran through `pnpm --filter @kokuin/records exec vitest run test/provider-routing.test.ts`.

| Regression | Observed red evidence | Green evidence |
| --- | --- | --- |
| Initial routing, carried digests, memo isolation, failures and mutation | Seven failures before production edits. Providers were ignored, carried digests were absent, and operational failures were refused or bypassed. | Included in the final records suite. |
| Payload rejection rollback | The corrected canonical-HLC fixture still resolved instead of rejecting before implementation. | Both owned and ambient transactions discard prior draft writes and leave clocks unchanged. |
| Holder-proof provider rejection | The outer proof check resolved `false` instead of throwing the original sentinel. | Private failure tagging preserves the original error through refusal catches. |
| Split provider capture | The second child invoked a replacement provider and rejected. | Every child uses the originally captured provider and bounds. |
| Method registry capture | Adding a rejecting resolver during suspended hashing changed verification to refusal. | The original registry snapshot verifies and carries the expected digest. |
| Filtered output ownership | Replacing an input entry or changing its payload returned unauthorised substituted content. | Filtering returns the authenticated owned records. |
| Captured key-version policy | Replacing `currentKeyVersion` during verification hid an otherwise authorised record. | The filter uses the captured callback. |

The final records suite contains 19 provider regressions and 300 existing tests.
Additional passing checks cover correctly framed small-order corpus refusal, signing serialisation, carried-digest construction failure and delayed signature verification before persistence.

The first rollback fixture used an incorrectly spelled HLC. It was corrected before its separate red run.
An early mechanical await pass also awaited a deliberate test gate. That test-only deadlock was corrected.
New test imports and the mutable registry fixture declaration required corrections before the final type check.
These were test/propagation corrections, not changes to the plan's architecture.

## Provider work and performance

Counters assert one signature verification and two hashes for a cold verified operation.
A warm same-policy operation performs only the existing op-address hash, skipping signature and content hashing.
Mutating a returned claim or digest cannot poison its remembered copy.
Concurrent rejecting policies cannot consume another provider's success.
False results and rejected operations remain retryable.

Range counters assert one leaf hash and one 36-byte hash per fingerprint.
The golden range exercise performs nine hashes, including three child summaries and requester comparison.
Signer deduplication and permutation invariance retain literal expected values.
Eight big-endian lanes, the four-byte count and 16-byte fingerprint output remain unchanged.

Synchronous content comparisons perform no hashing.
Apply shares one lazy payload-check Promise across its authorisation and persistence boundaries.
Vault decoding reuses its payload digest for branch-ID validation rather than hashing those bytes twice.
No duplicated verification or hashing was introduced at the migrated boundaries.
No native-routing or physical-workload performance claim is made.

## Verification

All commands ran from the worktree root. All final commands exited with status 0.

### Workspace build and type checks

```sh
PNPM_CONFIG_VERIFY_DEPS_BEFORE_RUN=false pnpm exec turbo run build:js build:types test:types --continue
```

```text
Tasks:    69 successful, 69 total
Cached:   54 cached, 69 total
Time:     6.786s
```

Full output: `/tmp/kokuin-pr3-build-verified.log`.
This includes workspace unit/integration fixtures and every declared type-check consumer.

### Required affected-unit suites

```sh
PNPM_CONFIG_VERIFY_DEPS_BEFORE_RUN=false pnpm exec turbo run test:unit --continue --concurrency=2 --filter @kokuin/records --filter @kokuin/vault --filter @kokuin/store-vault --filter @kokuin/controller
```

```text
@kokuin/records:     12 files, 319 passed,  2.60s
@kokuin/vault:       15 files, 154 passed,  1.37s
@kokuin/store-vault:  6 files, 263 passed,  7.73s
@kokuin/controller:  49 files, 814 passed, 17.03s
Tasks:              13 successful, 13 total
Cached:              6 cached, 13 total
Time:               17.938s
```

Total: **1,550 unit tests passed**. Full output: `/tmp/kokuin-pr3-units-verified.log`.
No timing-sensitive test timed out in this final run.
The full records suite also passed alone after the review fixes: 319 tests in 2.12s.
No isolated timeout rerun was necessary. No timeout configuration changed.

### Integration touching records

```sh
PNPM_CONFIG_VERIFY_DEPS_BEFORE_RUN=false pnpm --filter integration-tests exec vitest run test/store-vault.test.ts
```

```text
Test Files  1 passed (1)
Tests       400 passed (400)
Duration    64.85s
```

Full output: `/tmp/kokuin-pr3-integration-verified.log`.
The suite runs coordinator, replication and store-vault cases across SQLite and Postgres.
It covers projections, copies, branch convergence, authorisation and transaction outcomes.
Repo-wide searches identified this integration file as the records consumer.
The earlier integration run also passed 400 tests in 67.27s.

### Biome

```sh
./node_modules/.bin/biome ci .
```

```text
Checked 602 files. No fixes applied.
```

The report-inclusive final output is `/tmp/kokuin-pr3-biome-verified.log`.
No Node/Electron lock test was included in the requested package selection.
No `uv_uptime returned EPERM` failure occurred in these checks.

## Review and rulings

A fresh read-only reviewer examined the complete requested scope.
The reviewer identified two Important visibility ownership/policy issues.
Both received failing regressions, fixes and a passing full records run: 12 files, 319 tests, 2.12s.
No Critical, Important or Minor finding remains from that review.

Ruling: treat key-version callback replacement as Important because it changes authorisation during suspension.
The fix captures the callback before verification. The cost of leaving it unfixed would be a mutable authorisation decision.

Ruling: retain the prescribed PR 3/PR 4 boundary.
This delivery updates dependent awaits and comparisons without introducing vault's future provider configuration or metadata split.
The cost of applying a broader readiness interpretation would be overstating provider coverage before PR 4.

The reviewer declined to judge these areas. Their dispositions are explicit:

| Area set aside | Disposition and practical limit |
| --- | --- |
| PR 1 token/capability/JWE internals and PR 2 controller causal ordering/budgets/caches | Retain those completed contracts. The required controller suite provides regression coverage, not a new audit. |
| PR 4 vault hashing, metadata validation, outer/nested provider configuration, error tagging and direct-adapter ownership | Keep deferred as specified. This report makes no claim of complete vault provider adoption. |
| Full SQL rollback with injected vault providers | Keep deferred until vault injection exists. Records tests cover provider failures in owned and ambient transactions. Existing SQL integration covers the mechanical awaits. |
| Mutability inside providers, resolver closures and application hooks | Retain the immutable-provider contract. Capture callable identities, not arbitrary private callback state. |
| Native routing, hardware, mobile conformance, benchmarks and production readiness | Keep release qualifications open. All default routes remain noble. |
| Publication, downstream migration, registry versions and release graph | Leave separately authorised. Minor intents record API changes without publication. |
| Lockfile and clean-install reproducibility | Follow the explicit no-install/no-lock-edit rule. A normal dependency/lockfile workflow is still required before clean installation. |
| Exhaustive workspace fixture correctness and final build | Resolve through the implementer's root build/type checks and symbol searches, rather than reviewer inference. |
| Unrelated historical issues | Leave outside this scoped migration. No overall repository health claim is made. |
| Runtime execution by the reviewer | The reviewer used source and existing logs. All runtime verification in this report was executed by the implementer. |

## Deviations and concerns

- Git-based skill scripts, commits, branch integration and planning cleanup were omitted under the user's constraints.
- The requested report serves as the execution record. The full multi-PR plan remains open.
- Vault copies authenticated JSON metadata with a JSON round trip before suspension. Its ES-only type environment excludes `structuredClone`.
- The source migration used filesystem snapshots and TypeScript-aware edits. An overbroad initial propagation pass was reversed before scoped propagation continued.
- No synchronous noble compatibility shim, subpath export, transaction change or schema migration was added.
- The new records dependency is declared but its lockfile importer still requires normal synchronisation outside this no-install task.
- Vault-owned provider routing, expanded mobile conformance and final physical workload retesting remain later qualifications.
- A measured native route manifest remains a follow-on deliverable. No native route is promoted here.

## Full output files

All full outputs remain under `/tmp/kokuin-pr3-*.log` and `/tmp/kokuin-records-*.log`.
Key red outputs include `kokuin-records-red`, `kokuin-records-rollback-red`, `kokuin-pr3-proof-red`, `kokuin-pr3-range-red`, `kokuin-pr3-methods-red` and `kokuin-pr3-visibility-review-red`.
The final records review output is `/tmp/kokuin-pr3-records-review-green.log`.

Final verification: **69 build/type tasks, 1,550 unit tests, 400 integration tests and root Biome pass**.

## Review fixes

The three additional Important findings are fixed.
This section supersedes the earlier review-completion claim and direct-adapter ownership deferral.
Every finding received a regression test and an observed failure before its production fix.
No git command, dependency installation, dependency addition or lockfile edit was performed.
Every pnpm invocation used `PNPM_CONFIG_VERIFY_DEPS_BEFORE_RUN=false`.

### Authenticated operation ownership

Verified operations now contain deeply frozen, owned JSON claims, including nested metadata objects and arrays.
The operation itself is frozen. Its digest lives in a closure behind a non-configurable getter.
Replacing the claim, assigning a digest or redefining the getter throws `TypeError`.
Cold verification, memo copies and scoped-verifier copies use the same immutable construction.
Synchronous consumers therefore retain the digest and content authenticated by verification.

The provider regression initially reported **2 failed, 18 passed**.
Both failures showed that mutations expected to throw instead succeeded.
After the fix, the focused file reported **20 passed**.
The existing memo mutation test now expects refusal and retains its single-verification assertion.
The final records suite reports **326 passed**.

Red output: `/tmp/kokuin-review1-red.log`.
Focused green output: `/tmp/kokuin-review1-green.log`.
Full records green output: `/tmp/kokuin-review-records-green.log`.

### Validated apply snapshots

Apply retains its persistence snapshot and gives callbacks separate record copies, including separate payload buffers.
This covers precheck, authorisation, dependency, lock-key, after-authorisation and after-apply callbacks.
Authorisation receives separate stored copies and dependency-decision copies.
Persistence writes the original validated snapshot.
The existing lazy payload-check Promise remains shared across validation boundaries.

The initial regression reported **1 failed, 50 passed**.
Apply succeeded but stored `[9,9,9]` and an unsigned substituted token from `afterAuthorize`.
After the fix, the focused file reported **51 passed**.
The final suite also passes separate mutation cases for all six callback kinds.

Red output: `/tmp/kokuin-review2-red.log`.
Initial green output: `/tmp/kokuin-review2-green.log`.
Final callback coverage appears in `/tmp/kokuin-review-units.log`.

### Store-vault input snapshots and package sweep

`putCopy` and `retainEntryCandidate` snapshot records before their first await.
Validation, projection, indexed values, token insertion and payload storage use only those snapshots.
Suspended-resolver tests cover token replacement and payload-buffer mutation separately for both entry points.
These shared cases run against SQLite memory, SQLite files and Postgres.

The initial token-only regressions reported **2 failed, 104 skipped**.
Both stored `unsigned replacement` after verifying the original token.
After the fix, the focused run reported **2 passed, 104 skipped**.
The expanded final cases pass in the complete unit and integration suites.

The package sweep also found mutable inputs across signed writes, local row writes and coordinator writes.
Signed `write` now owns its records, payload buffers and preconditions before entering its transaction.
Pruning, wrapping suppression and branch rebuilding own their input addresses before suspension.
Local row write, update, move, delete and locking boundaries own their mutable data before suspension.
Coordinator writes own request data, plaintext, factor buffers and nested metadata before authority or provider calls.
Authority callbacks receive separate request data.
Opaque runtime objects, callbacks and transport contexts preserve their existing identity contracts.
Single-row delegation reaches the batch snapshot synchronously.
Read-only methods and migration setup require no persistence-input changes.

Two sweep regressions failed before these fixes.
A local write stored changed metadata and ciphertext.
A coordinator write encrypted plaintext changed while authority was suspended.
Both now pass, including the full **10-test** provider-methods file.

Red outputs: `/tmp/kokuin-review3-red.log` and `/tmp/kokuin-review3-sweep-red.log`.
Focused green outputs: `/tmp/kokuin-review3-green.log` and `/tmp/kokuin-review3-sweep-green.log`.

The first resolver fixture mutated payload and token together, causing refusal before insertion.
The token-only red run then demonstrated unsigned insertion directly.
An intermediate green attempt needed the new `snapshotRecord` export built before cross-package execution.
A mechanical parameter-renaming error was corrected before final verification.
The first full unit run found the old memo test's mutable-return assumption, which was updated as described above.
No final test failure remains.

### Final verification output

All commands ran from the worktree root and exited with status 0.
No extra hashing or verification was added.
Provider-routing counters remain unchanged, including cold, warm and range hashing assertions.
No timeout configuration changed and no slow-property-test rerun was required.

```sh
PNPM_CONFIG_VERIFY_DEPS_BEFORE_RUN=false pnpm exec turbo run build:js build:types test:types --continue
```

```text
Tasks:    69 successful, 69 total
Cached:   61 cached, 69 total
Time:     5.238s
```

Full output: `/tmp/kokuin-review-build.log`.

```sh
PNPM_CONFIG_VERIFY_DEPS_BEFORE_RUN=false pnpm exec turbo run test:unit --continue --concurrency=2 --filter @kokuin/records --filter @kokuin/vault --filter @kokuin/store-vault --filter @kokuin/controller
```

```text
@kokuin/records:     12 files, 326 passed
@kokuin/vault:       15 files, 154 passed
@kokuin/store-vault:  6 files, 269 passed
@kokuin/controller:  49 files, 814 passed
Tasks:              13 successful, 13 total
Cached:              7 cached, 13 total
Time:               15.184s
```

Total: **1,563 unit tests passed**. Full output: `/tmp/kokuin-review-units.log`.

```sh
PNPM_CONFIG_VERIFY_DEPS_BEFORE_RUN=false pnpm --filter integration-tests exec vitest run test/store-vault.test.ts
```

```text
Test Files  1 passed (1)
Tests       408 passed (408)
Duration    60.76s
```

Full output: `/tmp/kokuin-review-integration.log`.
The preceding integration run also passed all 404 cases before separate payload mutation cases were added.

```sh
./node_modules/.bin/biome ci .
```

```text
Checked 603 files. No fixes applied.
```

Report-inclusive output: `/tmp/kokuin-review-biome.log`.
Turbo emitted `Operation not permitted` IO warnings, but every final task passed.
The earlier lockfile synchronisation and later vault-provider migration qualifications remain unchanged.
