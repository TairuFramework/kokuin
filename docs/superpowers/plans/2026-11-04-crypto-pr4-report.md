# Crypto provider integration PR 4 report

Date: 2026-11-04.
Scope: identity stores, vault hashing and store integration.
Status: **DONE_WITH_CONCERNS**. Portable implementation and focused verification pass. All three additional review findings are fixed.

## Checklist implementation

| Plan checklist item | Implementation and evidence |
| --- | --- |
| Capture providers in software stores | Node, Electron, Expo and HD constructors retain a resolved provider in `#crypto`. All seven identity construction sites forward it. Sync provisioning remains synchronous. Constructor-option mutation tests pass. |
| Reopen conflicts | Node and Electron exercise default→custom, custom→omitted, custom→different, same→same and default→explicit-noble. Expo exercises all five with isolated module instances. Equality compares resolved provider references. |
| HD factories | Constructor, `fromSeed` and `fromMnemonic` all route signing through a counting provider. Derivation and agreement remain unchanged. |
| Expo SecureStore boundary | The constructor removes crypto from entry options and copies the remaining options. Its test checks the actual SecureStore call. |
| Vault primitive routing | Both direct BLAKE3 sites now use the selected provider. Every exported digest helper forwards options. Golden counters assert nine single calls and zero batch calls. |
| Freeze canonical outputs | Before production edits, the unchanged generated helpers produced literal digest, descriptor, entry-set and key-ID outputs. `vault/test/provider-routing.test.ts` freezes those values, including Unicode framing. Existing compatibility fixtures still pass. |
| Split metadata parsing and validation | `parseVaultRecordMeta` handles synchronous structure and is excluded from the public barrel. Public `vaultRecordMeta` snapshots metadata and awaits the owner/key-ID commitment. Ordering and dependency enumeration use only the structural parser. |
| Full metadata checks at boundaries | Precheck, authorisation, visibility, stored-key checks, branch introduction, version readers and direct adapter persistence await public validation. Wrong key commitments are refused before persistence. |
| Async decoding and callers | Vault tests, codec fixtures, shared SQL replication cases, projections and coordinator callers await the changed APIs. Integration fixtures type-check. |
| Own suspended inputs | IDs concatenate owned input bytes before awaiting. References capture canonical unique encoding. Metadata and payloads are copied before provider work. Descriptor checks capture expected digest. Suite wrap/unwrap copy factors, descriptors, secret inputs and byte views. Delayed-provider regressions cover metadata, unique Buffer subviews, descriptors and record payloads. |
| One coordinator provider | Construction resolves the outer provider and nested record provider once, snapshots both option objects, inherits the outer provider and rejects explicit conflicts before calls or storage work. |
| Forward through store integration | Provider options reach records apply, verification, payload checks, SQL row checks, candidate retention, projections, coordinator signing hashes, suite wrapping/unwrapping and factor digest checks. No SQL schema or transaction-joining change was made. |
| Capture resolver policy | Public record factories capture ordinary method arrays and bound resolver callables. A captured accessor supports the existing transaction-bound registry. Coordinator and records contexts snapshot ordinary method registries. |
| Preserve operational errors | Decode provider awaits sit outside codec refusal catches. `decodedAs` catches only `VaultRecordPayloadError`. Stored-row verification wraps structural corruption while preserving original provider failures. The authorisation regression injects a sentinel at each successive hash. |
| Revocation wrappers | Store-delegation captures options at construction and forwards crypto through its tracked backend/resolver wrappers. A custom DID resolver and sentinel provider prove both wrapper execution and provider forwarding. Replacing caller options cannot change the captured provider. |
| Mismatch and rollback | SQLite regressions cover payload mismatch, owner/key commitment mismatch and provider rejection after an earlier draft write, under standalone and ambient transactions. Caught late provider rejection also preserves existing copies when the surrounding transaction commits. |
| Validate before mutation | Incoming projection decoding completes before deleting existing copies. Projection consumes the decoded value and performs no hashing. No duplicate projection hash was added. |
| Retained signing paths | Browser tests count two WebCrypto signing calls, covering EdDSA and ES256. Ledger tests observe signing APDUs. Both assert zero provider sign/signBatch calls and verify the resulting signatures. |
| Preserve comparisons and constraints | Branch comparison and branch selection remain synchronous. Strict Ed25519 policy, unrelated primitives, parameter limits and `withStoreTransaction` semantics remain unchanged. |

## API changes

- Node/Electron parameter objects and HD constructor/factory options gain optional crypto.
- Expo constructor/open accept SecureStore options intersected with crypto options, without forwarding crypto to SecureStore.
- `digestParts`, `vaultKeyDigest`, `vaultWrappingDigest`, `vaultEntriesDigest`, `vaultEntryDigest` and `descriptorDigest` return `Promise<string>` and accept appended crypto options.
- `checkDescriptorDigest` returns `Promise<void>` and accepts crypto in its parameter object.
- `createVaultKeyID` and `createVaultKeyReference` return Promises and accept appended options.
- `vaultRecordMeta` returns a Promise and accepts options. `decodeVaultRecord` adds appended options to its existing Promise contract.
- Vault record-type options, key-version reader options, wrap/unwrap parameters, records parameters and coordinator parameters carry crypto.
- Factories, retained signing paths and branch comparisons keep their existing return contracts. `vaultHolderTypes` keeps its exact signature.

## Release intents

Extended existing minor intents rather than duplicating them:

- `.changeset/vault-crypto-provider.md`
- `.changeset/store-vault-crypto-provider.md`

Added minor intents for node, electron, expo, deterministic and store-delegation, each named `<package>-crypto-provider.md` under `.changeset/`.
No versions, release ledger or lockfile were edited. Dependency manifests and lockfile changes were already present when implementation started and remain preserved.

## Red-then-green evidence

| Regression | Observed failure before fix | Passing evidence |
| --- | --- | --- |
| Node routing/reopen | 2 failed, 27 passed | 29 passed |
| Electron routing/reopen | 2 failed, 27 passed | 29 passed |
| Expo routing/reopen | 4 failed, 19 passed | 23 passed |
| HD factory routing | 1 failed, 6 passed | 7 passed |
| Vault provider routing, snapshots and decoding failures | 5 failed, 2 passed | Final provider file: 9 passed |
| Coordinator routing/conflicts and provider rollback | 4 failed, 10 passed | Expanded provider-methods file: 20 passed |
| Store-delegation captured options | 1 failed, 21 passed | 22 passed |
| Public resolver capture, found in review | 1 failed, 8 passed | 9 passed |
| Caught late provider rejection, found in review | 2 failed, 18 passed; existing copies disappeared | 20 passed; existing copies survive both transaction modes |

The initial unchanged Node baseline passed 27 tests before the new regressions were actually written. The test-writing script first used unavailable `python`; switching to `python3` produced the recorded two-failure red run.
An intermediate Expo test compared noble instances across `vi.resetModules`; importing noble after the reset corrected that test identity error.
An overbroad await edit briefly awaited deliberate test gates and added redundant awaits in records; those edits were corrected, with records source restored to its prior content.
An existing synchronous throw assertion needed conversion to a rejected-Promise assertion. A new direct authorisation fixture initially used transaction-only ports outside a transaction; its read-only ports were corrected.
Early type checks found mock-narrowed provider fields, an invalid resolver return and a typed-array inference issue in fixtures. These are corrected.
An initial integration type run consumed outdated declarations; its resolution trace and final check pass after affected declaration builds.

## Verification

Only focused Vitest files ran, always with this exact prefix:

```sh
PNPM_CONFIG_VERIFY_DEPS_BEFORE_RUN=false taskpolicy -c background /Users/paul/.local/bin/with-deadline <seconds> pnpm --filter <package> exec vitest run <files>
```

Final focused commands and results:

| Package | Seconds | Files after `vitest run` | Passed | Failed |
| --- | ---: | --- | ---: | ---: |
| `@kokuin/node` | 60 | `test/lib.test.ts` | 29 | 0 |
| `@kokuin/electron` | 60 | `test/lib.test.ts` | 29 | 0 |
| `@kokuin/expo` | 60 | `test/lib.test.ts` | 23 | 0 |
| `@kokuin/deterministic` | 60 | `test/identity.test.ts` | 7 | 0 |
| `@kokuin/browser` | 60 | `test/identity.test.ts` | 7 | 0 |
| `@kokuin/ledger-device` | 60 | `test/provider.test.ts` | 6 | 0 |
| `@kokuin/store-delegation` | 60 | `test/revocation-checker.test.ts` | 22 | 0 |
| `@kokuin/vault` | 90 | `test/provider-routing.test.ts test/digest.test.ts test/key-reference.test.ts test/compatibility.test.ts test/record-types.test.ts test/record-codecs.test.ts test/record-endorsement.test.ts test/suite-1.test.ts test/vault.test.ts test/async-kem-wrap.test.ts` | 126 | 0 |
| `@kokuin/store-vault` | 90 | `test/provider-methods.test.ts test/vault.test.ts test/coordinator.test.ts` | 224 | 0 |

Total: **473 passed, zero failed, 20 focused files**. These are the latest results per selected file, not the sum of repeated invocations.
Full outputs are `/tmp/kokuin-pr4-node-green.log`, `electron-green`, `expo-green2`, `deterministic-green`, `browser`, `ledger-device`, `delegation-final3`, `vault-final2` and `store-final2`, with the same prefix and `.log` suffix.

### Additional exact focused command selections

The same mandatory prefix was used for these intermediate selections. Each row records the package, deadline and exact file suffix, followed by log results in execution order.

| Package / seconds / files | Log suffix and result |
| --- | --- |
| node / 60 / `test/lib.test.ts` | `node-red`: 2 failed, 27 passed; `node-green`: 29 passed |
| electron / 60 / `test/lib.test.ts` | `electron-red`: 2 failed, 27 passed; `electron-green`: 29 passed |
| expo / 60 / `test/lib.test.ts` | `expo-red`: 4 failed, 19 passed; `expo-green`: 1 failed, 22 passed; `expo-green2`: 23 passed |
| deterministic / 60 / `test/identity.test.ts` | `deterministic-red`: 1 failed, 6 passed; `deterministic-green`: 7 passed |
| vault / 60 / `test/provider-routing.test.ts` | `vault-red`: 5 failed, 2 passed; `vault-errors`: fixture failure, 7 passed; `review-vault-red`: 1 failed, 8 passed; `review-vault-green`: 9 passed |
| vault / 60 / `test/provider-routing.test.ts test/digest.test.ts test/key-reference.test.ts test/compatibility.test.ts` | `vault-green`: 3 failed, 35 passed; `vault-green2`: 38 passed |
| vault / 60 / `test/record-types.test.ts test/record-codecs.test.ts test/record-endorsement.test.ts test/suite-1.test.ts test/vault.test.ts test/async-kem-wrap.test.ts` | `vault-consumers`: 1 failed, 85 passed, one unhandled rejection from the outdated throw assertion |
| vault / 60 / `test/provider-routing.test.ts test/vault.test.ts` | `vault-fixes`: 23 passed |
| vault / 90 / final ten-file selection above | `vault-final`: 125 passed; `vault-final2`: 126 passed after adding the resolver regression |
| store-vault / 60 / `test/provider-methods.test.ts` | `store-red`: 4 failed, 10 passed; `store-green`: 14 passed |
| store-vault / 90 / `test/provider-methods.test.ts` | `store-rollback`: 18 passed; `review-store-red`: 2 failed, 18 passed; `review-store-green`: 20 passed |
| store-vault / 90 / final three-file selection above | `store-final`: 222 passed; `store-final2`: 224 passed after adding caught-failure regressions |
| store-delegation / 60 / `test/revocation-checker.test.ts` | `delegation`: 22 passed; `delegation-red`: 1 failed, 21 passed; `delegation-final`: 22 passed; `delegation-final2`: 1 failed, 21 passed because the custom DID fixture lacked historic resolution; `delegation-final3`: 22 passed with an exercised tracked historic resolver |

Every suffix in that table expands to `/tmp/kokuin-pr4-<suffix>.log`.
No workspace test suite, hardware test, installation, dependency addition or git write ran.

### Builds and type checks

Exact command forms, expanded over the listed affected packages:

```sh
PNPM_CONFIG_VERIFY_DEPS_BEFORE_RUN=false pnpm --filter @kokuin/<package> run build:types
PNPM_CONFIG_VERIFY_DEPS_BEFORE_RUN=false pnpm --filter @kokuin/<package> run test:types
```

Declaration builds: vault, store-vault, node, electron, expo, deterministic and store-delegation, all seven pass.
Test type checks: those seven plus browser and ledger-device, all nine pass.
The browser and ledger checks use their earlier successful logs; their production source did not change.
Final logs use `/tmp/kokuin-pr4-<package>-types-final.log` and `-test-types-final.log`.

```sh
PNPM_CONFIG_VERIFY_DEPS_BEFORE_RUN=false pnpm --filter integration-tests run test:types
PNPM_CONFIG_VERIFY_DEPS_BEFORE_RUN=false pnpm --filter integration-tests exec tsc --noEmit --skipLibCheck --traceResolution
PNPM_CONFIG_VERIFY_DEPS_BEFORE_RUN=false pnpm --filter @kokuin/vault run build:js
PNPM_CONFIG_VERIFY_DEPS_BEFORE_RUN=false pnpm --filter @kokuin/store-vault run build:js
./node_modules/.bin/biome ci .
```

All final commands pass. Integration types include the shared SQL fixtures without launching their runtime suites.
The trace output is `/tmp/kokuin-pr4-resolution.log`.
Report-inclusive Biome passes: 606 files, no fixes. Output: `/tmp/kokuin-pr4-biome-verified.log`.
Targeted `biome check --write` also ran over changed TypeScript files and the new provider file to apply repository formatting.

## Review and rulings

One independent read-only reviewer examined the uncommitted implementation and new tests. It ran no tests or builds.
No Critical issue was identified. Both Important findings were fixed with observed red-then-green regressions:

1. A late projection hash could fail after deleting previous copies. If the caller caught the failure inside its transaction, deletion could commit. Decoding now finishes before deletion and projection consumes its result.
2. Public record factories observed replacements of caller-owned resolver options. They now snapshot ordinary registries and bound callables while capturing the accessor used for internal transaction rebinding.

Ruling: preserve the transaction-bound accessor by capturing its getter identity, while snapshotting ordinary values. A wrong choice would bind verification to the wrong transaction or permit caller policy replacement. Existing scoped-method tests and the new replacement regression pass.
Ruling: preserve the established trusted-storage and immutable-provider contracts. This work does not reauthenticate trusted controller storage or make mutable provider implementations safe. Expanding either contract would require a separate design.
Ruling: retain the supplied worktree and use this report as the execution record. Git-based skill scripts, commits, integration and plan cleanup were omitted under the explicit no-git-write rule.

## Concerns and review limits

- Native routing has no supplied measured manifest in this task. No route promotion or native-consumer qualification is claimed.
- Browser and Ledger signing tests use portable runtime/mocked transport coverage. Physical hardware, mobile conformance and final physical workload benchmarks remain release qualifications.
- Runtime SQL checks here use SQLite memory. PostgreSQL, app end-to-end flows and broad workspace suites remain for the controller, as requested. Their shared modified fixtures type-check.
- Earlier controller ordering/cache implementations were unchanged and outside the fresh review. No new claim about their internals is made.
- The reviewer declined independent runtime verification because its assignment was read-only and prohibited test commands. The test evidence above is from the implementer.
- Preexisting dependency/lockfile changes were excluded from the reviewer’s implementation findings. The supplied dependency setup resolved without installation.
- Final report completeness was outside the review because preparation and verification were ongoing; the implementer records the final evidence here.


## Review fixes

All three additional findings are fixed. The earlier test totals remain historical evidence.
No git writes, installations, dependency changes or lockfile edits ran during these fixes.

| Finding | Observed red evidence | Observed green evidence |
| --- | --- | --- |
| Undefined factor inputs | Two new suite cases failed: nonempty wrapping returned `VaultSecretRejected`, while empty-passphrase wrapping unlocked. File: 2 failed, 41 passed. | Undefined entries are omitted before copying bytes. Both cases now throw `NoAvailableFactor`. File: 43 passed. |
| Sentinel test accepted swallowed errors | After strengthening the settled-outcome assertions, temporarily restoring the broad `decodedAs` catch produced a fulfilled outcome where rejection was required. File: 1 failed, 8 passed. | Restoring the narrow catch passed all 9 tests. Every reached rejection point requires the exact sentinel. Success requires an unreached rejection point. |
| Metadata snapshot error wrapping | Cyclic and bigint metadata each returned raw `TypeError`. File: 2 failed, 9 passed. | A synchronous snapshot catch wraps both failures in `VaultRecordPayloadError`, preserving their causes. File: 11 passed. Provider awaits remain outside refusal catches. |

The snapshot sweep covered every added byte copy in the uncommitted diff and the store-vault snapshot helpers.
Other added byte copies consume required byte fields or guarded optional values.
`new Uint8Array(factor.input)` snapshots a required wrapping input, rather than an optional unwrapping factor.
The recursive store-vault helper copies only actual `Uint8Array` instances and preserves undefined values.
Method snapshots preserve absent registries and optional callables.
No second optional-factor conversion was found.
The temporary broad catch was reverted before final verification.

Every red/green command used this exact prefix:

```sh
PNPM_CONFIG_VERIFY_DEPS_BEFORE_RUN=false taskpolicy -c background /Users/paul/.local/bin/with-deadline 60 pnpm --filter @kokuin/vault exec vitest run
```

| File suffix | Output logs under `/tmp/` |
| --- | --- |
| `test/suite-1.test.ts` | `kokuin-pr4-factors-red.log`, `kokuin-pr4-factors-green.log` |
| `test/provider-routing.test.ts` | `kokuin-pr4-sentinel-red.log`, `kokuin-pr4-sentinel-green.log`, `kokuin-pr4-metadata-red.log`, `kokuin-pr4-metadata-green.log` |

Final commands:

```sh
PNPM_CONFIG_VERIFY_DEPS_BEFORE_RUN=false taskpolicy -c background /Users/paul/.local/bin/with-deadline 90 pnpm --filter @kokuin/vault exec vitest run test/provider-routing.test.ts test/digest.test.ts test/key-reference.test.ts test/compatibility.test.ts test/record-types.test.ts test/record-codecs.test.ts test/record-endorsement.test.ts test/suite-1.test.ts test/vault.test.ts test/async-kem-wrap.test.ts
PNPM_CONFIG_VERIFY_DEPS_BEFORE_RUN=false pnpm --filter @kokuin/vault run test:types
PNPM_CONFIG_VERIFY_DEPS_BEFORE_RUN=false pnpm --filter @kokuin/store-vault run test:types
./node_modules/.bin/biome ci .
```

Final results: **130 tests passed, zero failed, ten focused files**. Both test type checks pass.
Report-inclusive Biome passes with no fixes. The deferred metadata-wrapper concern is resolved.
Existing native, hardware and broader verification qualifications above remain unchanged.
Final logs: `/tmp/kokuin-pr4-review-vault-final.log`, `/tmp/kokuin-pr4-review-vault-types.log`,
`/tmp/kokuin-pr4-review-store-vault-types.log` and `/tmp/kokuin-pr4-review-biome.log`.
Targeted `biome check --write` formatted the four edited TypeScript files before final verification.
