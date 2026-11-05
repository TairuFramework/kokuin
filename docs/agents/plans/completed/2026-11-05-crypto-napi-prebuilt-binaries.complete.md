# Prebuilt Node-API crypto binaries

Status: complete, pending the first release.

`@kokuin/crypto-napi` installs one `@kokuin/crypto-napi-<target>` package through `optionalDependencies`.
The targets are linux x64 and arm64 (glibc and musl), macOS x64 and arm64, and Windows x64 and arm64.

## Decisions

- Each binary builds on its own platform, so each is also tested there. Cross-compilation would ship binaries nothing had run.
- Linux glibc builds run on Debian 11, which sets the floor. The built binaries need glibc 2.30 symbols.
- The Linux containers receive a copy of the sources. On a bind mount, pnpm moved its store into the project and `pnpm exec cargo` failed.
- `napiBindingPath()` prefers a local `native/` binary, then the installed package. Bundles copy its result to `native/`.
- Only `crypto-napi` and its platform packages share a `versioning.fixed` group, because `crypto-napi` pins them exactly.
- Publishing stays local. CI attests each binary, and `scripts/ensure-crypto-napi.mjs` downloads the binaries of the exact release commit and verifies their attestations. A missing binary stops the release before anything publishes.
- The npm packages carry no npm provenance, because they are not published from CI.

## Verification

`crypto-napi-prebuilds.yml` runs the native provider tests and a clean-install smoke test on all eight targets. The smoke test requires `napi` with the platform package and `node` with `--omit=optional`.
A registry install of the real optional dependencies cannot run before the first publish.
