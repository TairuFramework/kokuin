# Crypto provider release preparation report

Date: 2026-11-04.
Status: **DONE_WITH_CONCERNS**.
Scope: portable documentation, release intents and downstream handoffs from the supplied brief.

## Delivered

- Added browser and store-controller minor intents.
- Rewrote existing migration intent bodies as concise, user-facing API summaries.
- Changed private controller-conformance's intent from `minor` to `none`.
- Extended `docs/reference/crypto-provider.md` into the provider adoption reference and updated its documentation-index entry.
- Added package migration notes for token, capability, JWE, controller, identity stores, vault, store-controller, store-delegation and store-vault.
- Added browser and Ledger dependency-alignment notes without inventing provider construction options.
- Updated crypto and crypto-native READMEs to remove stale migration-pending claims.
- Added a private controller-conformance README covering its seven asynchronous adapter members.
- Added records migration notes in its established reference location, `docs/reference/records.md`.
- Corrected existing controller reference examples and signature sketches to use Promises.
- Corrected stale synchronous vault key-ID comparisons in the vault reference and store-vault README.

The adoption reference contains every controller operation that became asynchronous, including internal source-module exports.
It distinguishes unchanged asynchronous contracts and synchronous constructors from newly asynchronous operations.
Package notes cover appended options, new parameter fields, `VerifiedRecordOp.contentDigest`, cached-store reopen conflicts and nested-provider conflicts.
They document strict verification, custom verifier precedence, immutable policy, error propagation and the trusted-storage boundary.
Persistent documentation contains no ephemeral planning links or implementation labels.

## Downstream handoffs

- `docs/agents/plans/next/2026-11-04-enkaku-crypto-provider-handoff.md`
- `docs/agents/plans/next/2026-11-04-kumiai-crypto-provider-handoff.md`

Both handoffs contain target dependency ranges, API differences, controller Promise lists, option examples, strict-verification expectations and test expectations.
The storage handoff also includes complete records and vault migration tables, carried-digest reconstruction and transaction expectations.
Sibling names appear only in these handoffs among changed persistent files.
Discovery coordinates are labelled as hints requiring baseline reinspection. No downstream repository was edited.

Source inspection verified public barrels, function signatures, builder fields, method-registry positions, identity-store options and coordinator conflict checks.
The handoffs preserve synchronous factories and retained WebCrypto/APDU signing.
They include no native route promotion or production-readiness claim.

## Release intent correction

The initial status and dry-run commands both exited 1:

```text
ERR_PNPM_VERSIONING_UNRELEASABLE_PACKAGE
controller-conformance-crypto-provider.md requests a minor release of
@kokuin/controller-conformance, which cannot release.
Remove the entry or change it to "none".
```

That package is private and explicitly ignored by versioning.
Changing its intent to `none` preserves the contract note without requesting publication or changing its 0.0.0 version.
The final preview omits this non-release intent.
This was release metadata, not a source defect. No source changes were necessary.

Ruling: use the matrix's recommended explicit store-controller minor.
Its exported controller contract changes despite unchanged store factory signatures.
The cost of a wrong choice would be a stronger release signal than a dependency patch alone.

Ruling: retain the existing crypto validation-cache patch intent.
It describes committed behaviour, although the matrix lists no crypto version change.
Removing it would lose the release note for that behaviour. Its version treatment remains a releaser concern.

Ruling: omit a Ledger intent because the dependency cascade already produces the required 0.2.6 patch.
An additional intent would duplicate the existing dependency-only release signal.

## Final release previews

Environment: Node v26.13.0, pnpm 12.16.1.
Both final commands exited 0. Dependency verification was disabled to avoid triggering installation work.

```sh
PNPM_CONFIG_VERIFY_DEPS_BEFORE_RUN=false pnpm change status
```

```text
Pending change intents:
  .changeset/browser-crypto-provider.md
  .changeset/capability-crypto-provider.md
  .changeset/controller-crypto-provider.md
  .changeset/crypto-point-validation-cache.md
  .changeset/deterministic-crypto-provider.md
  .changeset/electron-crypto-provider.md
  .changeset/expo-crypto-provider.md
  .changeset/jwe-crypto-provider.md
  .changeset/node-crypto-provider.md
  .changeset/records-crypto-provider.md
  .changeset/store-controller-crypto-provider.md
  .changeset/store-delegation-crypto-provider.md
  .changeset/store-vault-crypto-provider.md
  .changeset/token-crypto-provider.md
  .changeset/vault-crypto-provider.md

Release plan:
  @kokuin/browser: 0.2.4 → 0.3.0 (minor, via dependencies+intent)
  @kokuin/capability: 0.5.2 → 0.6.0 (minor, via dependencies+intent)
  @kokuin/controller: 0.2.5 → 0.3.0 (minor, via dependencies+intent)
  @kokuin/crypto: 0.1.0 → 0.1.0 (patch, via intent)
  @kokuin/deterministic: 0.2.4 → 0.3.0 (minor, via dependencies+intent)
  @kokuin/electron: 0.4.4 → 0.5.0 (minor, via dependencies+intent)
  @kokuin/expo: 0.4.2 → 0.5.0 (minor, via dependencies+intent)
  @kokuin/jwe: 0.1.1 → 0.2.0 (minor, via dependencies+intent)
  @kokuin/ledger-device: 0.2.5 → 0.2.6 (patch, via dependencies)
  @kokuin/node: 0.4.2 → 0.5.0 (minor, via dependencies+intent)
  @kokuin/records: 0.2.0 → 0.3.0 (minor, via dependencies+intent)
  @kokuin/store-controller: 0.4.1 → 0.5.0 (minor, via dependencies+intent)
  @kokuin/store-delegation: 0.3.0 → 0.4.0 (minor, via dependencies+intent)
  @kokuin/store-vault: 0.2.5 → 0.3.0 (minor, via dependencies+intent)
  @kokuin/token: 0.6.4 → 0.7.0 (minor, via intent)
  @kokuin/vault: 0.1.0 → 0.2.0 (minor, via dependencies+intent)
```

```sh
PNPM_CONFIG_VERIFY_DEPS_BEFORE_RUN=false pnpm version -r --dry-run
```

```text
Release plan:
  @kokuin/browser: 0.2.4 → 0.3.0 (minor, via dependencies+intent)
  @kokuin/capability: 0.5.2 → 0.6.0 (minor, via dependencies+intent)
  @kokuin/controller: 0.2.5 → 0.3.0 (minor, via dependencies+intent)
  @kokuin/crypto: 0.1.0 → 0.1.0 (patch, via intent)
  @kokuin/deterministic: 0.2.4 → 0.3.0 (minor, via dependencies+intent)
  @kokuin/electron: 0.4.4 → 0.5.0 (minor, via dependencies+intent)
  @kokuin/expo: 0.4.2 → 0.5.0 (minor, via dependencies+intent)
  @kokuin/jwe: 0.1.1 → 0.2.0 (minor, via dependencies+intent)
  @kokuin/ledger-device: 0.2.5 → 0.2.6 (patch, via dependencies)
  @kokuin/node: 0.4.2 → 0.5.0 (minor, via dependencies+intent)
  @kokuin/records: 0.2.0 → 0.3.0 (minor, via dependencies+intent)
  @kokuin/store-controller: 0.4.1 → 0.5.0 (minor, via dependencies+intent)
  @kokuin/store-delegation: 0.3.0 → 0.4.0 (minor, via dependencies+intent)
  @kokuin/store-vault: 0.2.5 → 0.3.0 (minor, via dependencies+intent)
  @kokuin/token: 0.6.4 → 0.7.0 (minor, via intent)
  @kokuin/vault: 0.1.0 → 0.2.0 (minor, via dependencies+intent)
```

Complete outputs: `/tmp/kokuin-pr5-change-status.log` and `/tmp/kokuin-pr5-version-dry-run.log`.
No non-dry-run version command ran.

## Matrix comparison

All 14 intended public minor targets match the matrix.
Ledger automatically moves from 0.2.5 to 0.2.6 through dependencies, as intended.
Crypto previews 0.1.0 to 0.1.0 despite its patch intent. The target matches, but release treatment differs from the matrix's unchanged-contract row.
This preview does not establish registry publication status or guarantee the next release preview remains identical.
Registry state and the crypto patch treatment require confirmation before authorised versioning or publication.

The preview omits crypto-native, OAuth and private conformance packages.
Their manifests remain at the matrix versions: crypto-native 0.1.0, OAuth 0.1.1 and both private conformance packages 0.0.0.
No unexpected package target appears. No extra Ledger intent is needed.

## Verification and limits

No test suite, build, installation, dependency addition, publication or git write ran.
Only documentation and Markdown release intents changed. Package versions, manifests, lockfile and release ledger remain unchanged.
The existing records lockfile importer already declares the crypto dependency, resolving the older report's importer concern in this baseline.
That source inspection does not establish clean-install reproducibility.

The initial root `biome ci .` check passed: 609 files, no fixes.
`git diff --check` passed. Final report-inclusive results are recorded below.
Static checks cover persistent-file restrictions, local link targets, API inventory and the release matrix.
Examples assume caller-supplied configuration and inputs. They were inspected against source, without running application or test code.
Prior implementation reports remain historical evidence. This task makes no fresh runtime verification claim.

## Open items

- Verify the separately measured route manifest against final module behaviour using exact route counters.
- Qualify native route promotion separately. Default integration routes remain noble.
- Run expanded mobile conformance, hardware checks and final physical workload retesting.
- Confirm registry publication state and crypto patch treatment before applying the release plan.
- Perform separately authorised downstream implementation and publication after package availability is confirmed.
- Earlier reports record sandbox lock failures and deferred cache/budget coverage. This documentation task did not rerun or resolve them.

The requested portable preparation is complete. Release qualification and downstream implementation remain separate work.

## Independent review

A fresh read-only reviewer checked the documentation, intents, source signatures, Promise inventory and supplied release previews.
The review identified reversed ES256 test wording in both handoffs. Both now require low-S acceptance and high-S rejection.
A stale migration-pending statement found during review was also corrected in crypto and crypto-native READMEs.
No other concrete finding remained. The reviewer ran no builds, suites or runtime qualification.

Ruling: retain native qualification and runtime behaviour as review limits under the brief's explicit exclusions.
Portable documentation review cannot replace mobile conformance or physical workload evidence.
The cost of treating it as qualification would be an unsupported production-readiness claim.

## Final verification evidence

- `./node_modules/.bin/biome ci .`: exit 0, 610 files checked, no fixes.
- `git diff --check`: exit 0.
- Protected-file diff for all package manifests, `pnpm-lock.yaml` and `.changeset/ledger.yaml`: exit 0, no differences.
- Static documentation check: exit 0, 39 persistent Markdown files and 20 matrix rows checked against both previews.
- Static scope, forbidden references, sibling names, local links, anchors, ES256 wording and complete controller asynchronous-export inventory: all pass.

Outputs: `/tmp/kokuin-pr5-biome.log` and `/tmp/kokuin-pr5-static-check.log`.
No runtime suite was needed or permitted for this documentation-only change.
