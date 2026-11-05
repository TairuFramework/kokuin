---
'@kokuin/crypto-napi': minor
---

Install prebuilt binaries for linux x64 and arm64 (glibc and musl), macOS x64 and arm64, and Windows x64 and arm64 through `optionalDependencies`. `napiBindingPath()` now returns the installed package's binary when no local `native/` binary exists. Other platforms, and installs that omit optional dependencies, still use `nodeCrypto`.
