# Document the expo and electron `provideIdentitySync` twins

**Origin:** `completed/2026-07-18-auth-docs-provide-identity-refresh.complete.md` — known gap.
**Priority:** low. Nothing currently documented is false; this is an omission.

## What

`@kokuin/expo` (`packages/expo/src/store.ts`) and `@kokuin/electron`
(`packages/electron/src/store.ts`) both expose a `provideIdentitySync` twin alongside the async
`provideIdentity`. Only `@kokuin/node`'s sync twin is shown in the docs.

Sections to update, in both files, so they stay consistent with each other:

- `docs/reference/auth.md` — the `@kokuin/expo` and `@kokuin/electron` keystore sections.
- `docs/skills/auth.skill.md` — the corresponding expo and electron patterns.

## Watch out

The `lockPath` caveat documented on Node's sync twin is **Node-specific** — `provideIdentitySync`
throws there when the store was opened with a `lockPath`, because a file lock cannot be acquired
synchronously. Do not copy that caveat onto expo or electron without checking whether an
equivalent constraint exists in those backends.

Verify each signature against the package source before writing; the whole point of the refresh
this came out of was that the docs had drifted from the actual exports.
