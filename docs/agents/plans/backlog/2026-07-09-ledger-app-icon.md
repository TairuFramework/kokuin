# Ledger app icon is a placeholder

**Status:** backlog
**Origin:** `completed/2026-07-09-firmware-consent-and-signing-safety.complete.md`

## Context

`apps/ledger/icons/kokuin_app_14px.gif` is the LedgerHQ boilerplate glyph, copied in when the
NBGL UI landed because the Nano home screen and every review screen need an icon to render. It
is not Kokuin branding.

Non-blocking: the firmware builds, boots and reviews correctly with it. It becomes a real
concern only when the app is submitted to the Ledger app catalog, which also wants the Nano X
variant — see `backlog/ledger-root-identity.md`.

## Work

- Draw a real 14px Kokuin glyph (刻印 / seal motif) and replace the placeholder.
- The Makefile already declares `ICON_NANOX` and `ICON_NANOSP`; both currently point at the
  same placeholder file. Supply whatever per-device sizes the catalog requires.
