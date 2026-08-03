# kokuin roadmap

kokuin (刻印) is the identity / auth / keys layer: tokens, capabilities, and per-runtime
keystores. **Overriding goal: harden the auth surface before external consumers depend on it.**

Updated 2026-08-03. The 2026-07-02 audit (`completed/2026-07-02-audit.complete.md`) drove the
last month of work and is now mostly closed:

| Severity | Closed | Open |
|----------|--------|------|
| Critical | 4 of 5 — prefix escalation, silent signing oracle, `alg:none`, electron clobber | #5 changeset fixed group |
| High | 5 of 8 — commit timing, `provideAsync` races, `kid` relationship, audience validation, electron encryption check | firmware-in-CI, turbo `dependsOn`, SLIP-0010 vector |

Every remaining audit item is build and release plumbing, not auth correctness. The security
work that remains came from elsewhere: one live fail-open found downstream in kubun.

## Now (in priority order)

1. **`did:peer:4` revocation records are unverifiable** —
   `next/2026-08-03-peer4-revocation-records-are-unverifiable.md`. A peer:4 grantor can revoke
   nothing: audience-less tokens carry the short form in `iss`, which no recipient can resolve.
   Latent rather than live (kokuin's production paths are all `did:key` today) but it is a trap
   door — `chooseMethod` picks peer:4 automatically for any multi-key identity, which is the
   natural shape once a KEM key sits on the identity. Needs a design decision between three
   trade-offs before any code.
2. **Verified-token mutation and residual decode hardening** —
   `next/2026-07-10-verified-token-mutation-and-decode-hardening.md`. Nothing remotely
   reachable. Bundled with item 1: same two files, and its doc-size guard sits in the same
   resolver path.
3. **Ledger protocol hardening** — `next/2026-07-02-ledger-protocol-hardening.md`. Promoted from
   backlog on 2026-08-03: `encodeDerivationPath` turns a malformed path into a valid-looking
   `m/0'` with no error at any layer, so a wrong key is derived silently. Also gates the APDU
   protocol version, never checked today.
4. **Release config** — `next/2026-08-03-release-config-fixed-group-and-license.md`. The fixed
   group is unconfigured, so five packages that should ship together sit at five versions and
   drift further every release. Plus the missing LICENSE, which blocks npm publication outright.
   Small, and the drift compounds until it lands.
5. **CI pipeline gating** — `next/2026-07-02-ci-release-gating.md`. The remaining three audit
   High items, plus workflow pinning and permanent doc-snippet typechecking.
6. **Verify the e2e-node keyring behaviour on Linux** —
   `next/2026-08-03-verify-e2e-node-keyring-on-linux.md`. Reading one CI run; cheaper to close
   than to carry.

Items 1–3 are correctness. Items 4–6 are the pipeline that should have caught them.

## Later (backlog, no committed timeline)

- `2026-08-03-downstream-keystore-contract-adoption.md` — enkaku and kumiai onto the shipped
  breaking changes; kumiai is two minors behind on capability
- `2026-07-24-e2e-web-playwright-ci-parallelism.md` — CI wall-clock, no behaviour change
- `2026-07-18-document-expo-electron-sync-twins.md` — documentation omission
- `2026-07-16-browser-x25519-webkit-idb.md` — tracks an upstream WebKit bug; revert the
  workaround when it lands. Carries an accepted security regression until then
- `2026-07-02-security-model-docs.md` — blocked on item 1, which decides the `iss` behaviour
  the prose would describe
- `2026-07-02-otel-docs-and-release-policy.md` — package README, unused dependency
- `2026-06-30-ledger-root-identity.md` — multi-device support, app-catalog submission, app icon
- `2026-06-30-post-quantum-algorithms.md` — ML-DSA / ML-KEM, four phases
- `2026-01-30-jwe-multi-recipient.md` — shares `jwe.ts` with post-quantum phase 3

## Toward 1.0

Per stack policy, kokuin promotes to 1.0 whole, once its surface is stable. Three prerequisites
remain:

- **Item 1 resolved.** It is the last open finding that changes verification behaviour, and it
  changes the wire format of `iss` for a whole class of tokens. Settling it after 1.0 would be
  a breaking change; settling it now is free.
- **The security model written** (`backlog/2026-07-02-security-model-docs.md`) — blocked on the
  above.
- **Releases actually gated** (items 4 and 5). Publishing a 1.0 from a pipeline that does not
  build the firmware, does not assert derivation vectors, and cannot hold five packages at one
  version is how a stable surface stops being stable.

The `KeyStore` / `KeyEntry` contract prerequisite is met: documented in `@kokuin/token` and
enforced across every backend by `@kokuin/keystore-conformance`
(`completed/2026-07-14-keystore-contract.complete.md`).

## Completed since the last roadmap update

- `2026-07-18-auth-docs-provide-identity-refresh.complete.md` — auth docs to the store-method
  identity API
- `2026-07-14-keystore-contract.complete.md` — the contract, reconciliation, conformance suite
- `2026-07-10-token-verification-hardening.complete.md` — `alg:none`, base58 DoS bounds
- `2026-07-09-firmware-consent-and-signing-safety.complete.md` — on-device consent gating
