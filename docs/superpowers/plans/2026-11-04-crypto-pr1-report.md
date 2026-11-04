# Crypto provider integration PR 1 report

Date: 2026-11-04.
Scope: token, capability and JWE provider threading only. PR 2 was not started.
Status: **implemented, verification limited by sandbox restrictions**.
Build, repo-wide type checks and Biome pass. Twelve Node/Electron lock tests cannot pass in this sandbox.

## Changes per package

| Package | Changes | Release intent |
| --- | --- | --- |
| `@kokuin/token` | Identity helpers capture providers. Both EdDSA signing sites and default EdDSA/ES256 verification use them. Signature memo scopes and verified-object provenance isolate policies. Verification snapshots bytes, claims, overrides, methods, cache functions and audiences. | Minor, targeting 0.7.0 |
| `@kokuin/capability` | Parent creation, chain checks and capability checks forward captured provider options. Revocation factories capture providers and retain mandatory historic verification. A private failure wrapper preserves original operational rejections through refusal catches. | Minor, targeting 0.6.0 |
| `@kokuin/jwe` | Both unwrap branches forward provider and captured overrides, covering JWS and both nested encryption modes. Wrapping retains identity-owned signing. | Minor, targeting 0.2.0 |

Each package has `test/provider-routing.test.ts` and its own `.changeset` intent.
The provider reference documents adoption, override precedence, cache provenance, strict verification and retained paths.
`CryptoOptions`, `VerifySignedPayloadInput` and `verifySignedPayload` are available through the token barrel.
Existing overloads and identity construction return types remain intact.

The controller supplied the three `@kokuin/crypto: workspace:^` declarations, lockfile changes and installation before continuation.
No additional dependency was needed. This implementation ran no installs or git writes.

## Implemented checklist

- Both identity signing implementations use their captured provider over the exact raw JWS signing bytes.
- ES256 receives compact signatures and raw messages. The provider hashes once and rejects high-S signatures.
- Algorithm-specific overrides retain precedence. Missing overrides reach the selected provider.
- Parent creation, direct delegation chains, capability checks, revocation backend and checker route verification through the selected provider.
- Revocation `verifyOptions` includes `crypto` and always supplies `historic: true`.
- Both unwrap branches forward providers, including JWS-in-JWE and JWE-in-JWS.
- Signature memo entries use weak verifier identities and globally bounded numeric scopes.
- The 8192-entry, 16 KiB per-message and 8 MiB aggregate message-byte limits remain unchanged.
- Verified objects retain provider, relevant verifier, resolver, cache and method provenance.
- Cross-policy objects reverify. `isVerifiedToken` still indicates prior verification.
- Signature/key/message inputs, overrides, resolution methods, cache methods and audience arrays are captured before suspension.
- Object verification returns owned claims decoded from authenticated signing data.
- Existing time, audience, historic-key, payload mutation and custom-verifier checks remain covered.
- False results and operational rejections never populate success memos. Concurrent provider and retry tests assert this.
- Documentation and option exports are updated.

## Test-first evidence

Initial token routing regressions: `Tests  8 failed | 1 passed (9)` before implementation.
Initial capability routing regressions: `Tests  4 failed (4)` before implementation.
Initial JWE routing regressions: `Tests  3 failed | 1 passed (4)` before implementation.
Failures showed ignored provider options, cross-policy cache reuse, mutable inputs and acceptance of the crafted ZIP-215 forgery.
Plain envelopes already avoided verification. One pre-implementation snapshot case also passed.
Independent routing, negative-policy and strict-verification regressions supplied the failing evidence.

Additional regressions failed before their fixes:

- Resolver prototype methods were lost when policy capture spread class instances.
- A replaced DID cache writer ran after verification suspended.
- A suspended capability chain switched providers after the caller changed its options.
- Both object and serialised token branches accepted a mutated audience policy.

Corpus-based strict tests reuse the identity and mixed-order A fixtures from `crypto-conformance/vectors/corpus.json`.
Mixed-order signatures are regenerated against correctly framed JWS messages for challenges congruent to zero and three modulo four.
The tests establish that old ZIP-215 verification accepts them, while default token verification rejects them.
Capability and revocation paths also reject message-independent small-order forgeries under the strict default.
Ordinary deterministic signatures, retained signing paths, and existing workspace callers run in the affected package suites.

## Verification commands

Every pnpm command used `PNPM_CONFIG_VERIFY_DEPS_BEFORE_RUN=false`.
Every test run used `/Users/paul/.local/bin/with-deadline 900 taskpolicy -c background`.

```sh
PNPM_CONFIG_VERIFY_DEPS_BEFORE_RUN=false pnpm exec turbo run build:js build:types
PNPM_CONFIG_VERIFY_DEPS_BEFORE_RUN=false /Users/paul/.local/bin/with-deadline 900 taskpolicy -c background pnpm exec turbo run test:types --continue
PNPM_CONFIG_VERIFY_DEPS_BEFORE_RUN=false /Users/paul/.local/bin/with-deadline 900 taskpolicy -c background pnpm exec turbo run test:unit --continue --concurrency=2 --filter='...@kokuin/token' --filter='...@kokuin/capability' --filter='...@kokuin/jwe' --filter='!integration-tests' --filter='!e2e-*' --filter='!@kokuin/ledger-tests' -- --maxWorkers=2
./node_modules/.bin/biome ci .
```

Final build output:

```text
 Tasks:    44 successful, 44 total
Cached:    25 cached, 44 total
```

Final repo-wide type-check output:

```text
 Tasks:    47 successful, 47 total
Cached:    9 cached, 47 total
```

Final unit invocation output, pasted by package:

```text
@kokuin/store-controller: Tests  1 failed | 32 passed | 1 skipped (34)
@kokuin/jwe: Tests  69 passed (69)
@kokuin/capability: Tests  221 passed (221)
@kokuin/store-delegation: Tests  84 passed (84)
@kokuin/records: Tests  300 passed (300)
@kokuin/vault: Tests  154 passed (154)
@kokuin/keystore-conformance: Tests  6 passed (6)
@kokuin/electron: Tests  3 failed | 47 passed (50)
@kokuin/expo: Tests  36 passed (36)
@kokuin/deterministic: Tests  35 passed (35)
@kokuin/token: Tests  308 passed (308)
@kokuin/ledger-device: Tests  23 passed (23)
@kokuin/store-vault: Tests  263 passed (263)
@kokuin/node: Tests  9 failed | 47 passed (56)
@kokuin/browser: Tests  48 passed (48)
@kokuin/controller: Tests  793 passed (793)

 Tasks:    32 successful, 35 total
Cached:    0 cached, 35 total
Failed:    @kokuin/electron#test:unit, @kokuin/node#test:unit, @kokuin/store-controller#test:unit
```

That invocation recorded 2466 passed, 13 failed and one skipped test across 16 packages.
The store-controller timeout passed on a complete isolated package rerun:

```sh
PNPM_CONFIG_VERIFY_DEPS_BEFORE_RUN=false /Users/paul/.local/bin/with-deadline 900 taskpolicy -c background pnpm --filter @kokuin/store-controller run test:unit -- --maxWorkers=1
```

```text
 Test Files  1 passed (1)
      Tests  33 passed | 1 skipped (34)
```

Latest package results therefore total **2467 passed, 12 failed, one skipped**.
All 27 new provider-routing tests passed: token 18, capability five and JWE four.
The original unit invocation remains red. The rerun does not erase its recorded timeout.

Final Biome output:

```text
Checked 593 files in 165ms. No fixes applied.
```

`git diff --check` also passed.

### Remaining unit failures

All twelve failures originate in unchanged lock code calling `node:os.uptime()` through `@sozai/lock`.
The error is `uv_uptime returned EPERM (operation not permitted)`.
A direct standalone Node invocation reproduces it, without importing this repository.
No dependency patch, OS shim or test exemption was introduced.

```text
@kokuin/electron:test:unit:  FAIL  test/lock.test.ts > ElectronKeyStore lockPath > provideAsync works with a lockPath set
@kokuin/electron:test:unit:  FAIL  test/lock.test.ts > ElectronKeyStore lockPath > concurrent provideAsync calls converge on one key
@kokuin/electron:test:unit:  FAIL  test/lock.test.ts > ElectronKeyStore lockPath > no lockfile is left behind
@kokuin/node:test:unit:  FAIL  test/lock.test.ts > NodeKeyStore lockPath > provideAsync works with a lockPath set
@kokuin/node:test:unit:  FAIL  test/lock.test.ts > NodeKeyStore lockPath > re-reads inside the lock and returns a peer’s key rather than clobbering it
@kokuin/node:test:unit:  FAIL  test/lock.test.ts > NodeKeyStore lockPath > concurrent provideAsync calls converge on one key
@kokuin/node:test:unit:  FAIL  test/lock.test.ts > NodeKeyStore lockPath > re-reads inside the lock even when #encoded carries a stale list()-time snapshot
@kokuin/node:test:unit:  FAIL  test/lock.test.ts > NodeKeyStore lockPath > a lockPath does not leak a lockfile after the call
@kokuin/node:test:unit:  FAIL  test/lock.test.ts > adversarial keyIDs > the path-traversal keyID "../../../etc/passwd" touches nothing outside the lockPath
@kokuin/node:test:unit:  FAIL  test/lock.test.ts > adversarial keyIDs > the path-traversal keyID "..\\..\\windows\\system32" touches nothing outside the lockPath
@kokuin/node:test:unit:  FAIL  test/lock.test.ts > adversarial keyIDs > the path-traversal keyID "/absolute/path" touches nothing outside the lockPath
@kokuin/node:test:unit:  FAIL  test/lock.test.ts > adversarial keyIDs > the path-traversal keyID "nested/../../escape" touches nothing outside the lockPath
```

The initial main-run store-controller timeout was `registers and round-trips a stored log` in `test/controller-store.test.ts`.
The earlier capability timeout was `can it mint a fresh capability granting itself everything?` in `test/own-historic-mint.test.ts`.
Both passed on isolated reruns. The one skipped store-controller case is pre-existing.


## Review and rulings

An independent read-only reviewer examined source, tests, release intents and the binding requirements.
No Critical finding was reported.
The reviewer called audience mutation a minor pre-existing gap.
It was treated as Important because mutable audience policy can change authorisation during suspension, and fixed with failing regressions.

Deferred minor coverage: explicit cross-provider eviction and aggregate-byte-limit stress tests.
The implementation retains one globally bounded map. Existing memo tests cover entry eviction and per-message size boundaries.

## Deviations and concerns

- No caller syntax changes were needed because all new options are optional.
- No existing test requiring ZIP-215 acceptance was identified. New rejection regressions establish the strict cutover explicitly.
- Store-delegation's tracked-options spread test is deferred to the identity/store work, as the plan explicitly permits.
- The full multi-PR plan remains open. Its design, later checklists and ephemeral planning files are preserved.
- Source, dependency versions and package scripts outside the authorised scope were left alone.
- An early concurrent run timed out `capability/test/own-historic-mint.test.ts` after five seconds. Its isolated rerun passed.
- Lower unit concurrency avoids host contention without changing test configuration or increasing timeouts.
- Sandbox restrictions prevent `os.uptime()` independently of repository code. A direct Node invocation reproduces `uv_uptime returned EPERM`.
- Turbo also emits sandbox IO warnings. Their presence alone does not determine task success.
- All default routes remain noble. Native routing still requires a stored, measured manifest.
- Strict noble subgroup checks cost more CPU. Expanded conformance and final physical workload retesting remain release qualifications.

## Existing suites intentionally unrun

- `tests/integration`: concurrency, store-controller, store-vault, legacy-names and store-delegation suites with SQLite/Postgres infrastructure.
- `tests/ledger`: Speculos suite and its emulator runner.
- `tests/e2e-electron`: sign/verify and two-identity restart tests.
- `tests/e2e-node`: race test.
- `tests/e2e-web`: sign/verify, two-identity and durable-reload tests.
- `tests/e2e-expo`: Maestro app flows and crypto strict-noble, benchmark and gate tests.

No Docker/Postgres, physical-device, e2e app or simulator test ran.
Repo-wide type checking includes their declared type-check tasks without launching those suites.
