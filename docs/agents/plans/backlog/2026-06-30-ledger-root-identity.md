# Ledger root identity: remaining work

**Status:** backlog
**Relocated from enkaku** in the 0.18 stack split (2026-06-30). Prose converted to kokuin terms
on 2026-08-03 (triage) — it had described the pre-split `@enkaku/*` packages for a month after
the move. Predecessor links below point at the **enkaku** repo's `completed/` folder, not this
one.

**Predecessors (enkaku repo):**
- `completed/2026-03-26-ledger-identity.complete.md` — Ledger identity + HD keystore
- `completed/2026-03-28-agent-primitives.complete.md` — hub mailbox, revocation, delegation

## Context

The original plan covered a root-identity story spanning framework primitives and kumiai
integration. The primitives are done and now live here as `@kokuin/ledger-device`,
`@kokuin/capability` and `@kokuin/token`:

- Capability delegation via `createCapability`.
- Revocation: `RevocationRecord`, `RevocationBackend`, `createRevocationChecker` as a
  `VerifyTokenHook`.
- Single-recipient JWE, which is the primitive kumiai needs.

GroupArchiver (MLS epoch key archival) is kumiai scope, tracked in that repo. Multi-recipient
JWE for archival to multiple roots is `backlog/2026-01-30-jwe-multi-recipient.md`.

The revocation primitive listed above had a fail-open for `did:peer:4` signers — audience-less
records carried an unresolvable short-form `iss`. Fixed on 2026-08-04, see
`completed/2026-08-04-peer4-audienceless-iss-and-verify-hardening.complete.md`. "Revocation is
done" now holds for `did:peer:4` identities too.

## Work

### Multi-Ledger support

Allow personal and organisational root identities on separate Ledger devices.
`@kokuin/ledger-device` assumes one connected device. Surface area:

- Multiple `LedgerIdentity` instances against distinct transports and sessions.
- Identity selection UX is deferred to consumer apps. The framework only needs to stop assuming
  a single device.

### Ledger app catalog submission

Submit the BOLOS app in `apps/ledger` to Ledger's app catalog. Out-of-band work — paperwork,
audits, signing. Track scheduling separately once prioritised.

### Replace the placeholder app icon

Merged here on 2026-08-03 from `backlog/2026-07-09-ledger-app-icon.md`, because it only matters
at catalog submission, which this item owns.

`apps/ledger/icons/kokuin_app_14px.gif` is the LedgerHQ boilerplate glyph, copied in when the
NBGL UI landed — the Nano home screen and every review screen need an icon to render. It is not
Kokuin branding. Non-blocking: the firmware builds, boots and reviews correctly with it.

- Draw a real 14px Kokuin glyph (刻印 / seal motif) and replace the placeholder.
- The Makefile already declares `ICON_NANOX` and `ICON_NANOSP`; both point at the same
  placeholder. Supply whatever per-device sizes the catalog requires.

## Out of scope

- GroupArchiver — kumiai.
- Multi-recipient JWE — `backlog/2026-01-30-jwe-multi-recipient.md`.
- APDU protocol version gating and path validation — now
  `next/2026-07-02-ledger-protocol-hardening.md`.
