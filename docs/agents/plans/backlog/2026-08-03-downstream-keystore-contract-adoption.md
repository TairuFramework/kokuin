# Downstream adoption of the keystore contract changes

**Status:** backlog
**Origin:** `completed/2026-07-14-keystore-contract.complete.md` — "`@enkaku` / `@kumiai` are
updated as a follow-up, not here."

## Context

The keystore contract work shipped breaking changes across the fixed group (constructor params
moved to a single `*Params` object, `ElectronKeyStoreOptions` → `ElectronKeyStoreParams`, the
`KeyEntry` / `MutableKeyEntry` split, the store-method identity surface). Consumers were left
for a follow-up that no plan item ever tracked.

Half of it happened by drift, so the remainder is invisible. As of 2026-08-03:

| Repo | `@kokuin/token` | `@kokuin/capability` | Other |
|------|-----------------|----------------------|-------|
| enkaku | `^0.3.0` — current | `^0.2.1` — current | `@kokuin/electron ^0.4.0` — current |
| kumiai | `^0.3.0` — current | **`^0.1.0` — two minors stale** | `@kokuin/expo ^0.3.0` — current |

Both catalogs are in each repo's `pnpm-workspace.yaml`.

## Work

- Bump `@kokuin/capability` to `^0.2.1` in `kumiai/pnpm-workspace.yaml`, then fix the call
  sites the capability authorization fixes broke (prefix escalation, `kid`/`aud` checks,
  signed revocation). Six kumiai packages depend on `@kokuin/token`; only `hub-client` and
  `hub-server` list capability.
- Confirm enkaku actually compiles against the versions it already names — a matching catalog
  range is not proof the call sites were migrated.
- Check whether either repo constructs keystores positionally, which the `*Params` change
  broke silently for any untyped call site.

## Out of scope

- Any further kokuin-side API change. This item only moves consumers onto what already shipped.
