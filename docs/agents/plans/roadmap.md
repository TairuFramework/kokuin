# kokuin roadmap

kokuin (刻印) is the identity / auth / keys layer: tokens, capabilities, and per-runtime
keystores. **Overriding goal: harden the auth surface before external consumers depend on
it.** The 2026-07-02 audit (`completed/2026-07-02-audit.complete.md`) found privilege
escalation, a silent signing oracle, and data-loss bugs — these gate everything else.

## Now (in priority order)

Sequenced per the audit's suggested order — security correctness first, then make CI
actually gate, then the contract + tests that prevent regressions.

1. **Security correctness fixes** — small, verified, each independently shippable:
   - `next/2026-07-02-capability-authorization-fixes.md` — prefix escalation (#1), kid/aud, revocation
   - `next/2026-07-02-token-verification-hardening.md` — `alg:none` (#3), nullish guards, peer4 DoS
   - `next/2026-07-02-keystore-correctness-fixes.md` — electron clobber (#4), commit-timing, races
   - `next/2026-07-02-firmware-consent-and-signing-safety.md` — consent UX (#2), `req_type` reset
2. **CI + release gating** — `next/2026-07-02-ci-release-gating.md`: fixed changeset group
   (#5), test-depends-on-build, ledger-in-CI, SLIP-0010 vectors, `@main` pinning, LICENSE.
3. **KeyStore contract + adversarial tests** — `next/2026-07-02-keystore-contract-and-adversarial-tests.md`:
   the highest-leverage item; specify the central contract, reconcile implementations, add
   adversarial tests that would have caught the above.

## Later (backlog, no committed timeline)

- `backlog/2026-07-02-ledger-protocol-hardening.md` — protocol version gate, path validation
- `backlog/2026-07-02-security-model-docs.md` — security-model prose for the auth layer
- `backlog/2026-07-02-otel-docs-and-release-policy.md` — document otel, wire/drop dead surface
- `backlog/ledger-root-identity.md` — multi-Ledger support, app-catalog submission (pre-existing)
- `backlog/2026-01-30-jwe-multi-recipient.md` — multi-recipient JWE (pre-existing)
- `backlog/post-quantum-algorithms.md` — PQ algorithms (pre-existing)

## Toward 1.0

Per stack policy, kokuin promotes to 1.0 whole once its surface is stable. Prerequisites:
the audit's Critical + High items resolved, the KeyStore/KeyEntry contract documented and
enforced, and the security model written.
