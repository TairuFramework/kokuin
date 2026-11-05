#!/bin/sh
# Builds this platform's @kokuin/crypto-napi-<target> binary, then tests it through the provider and
# through a clean install. Runs on CI hosts and in the Linux containers.
set -eu

if [ -f /etc/alpine-release ]; then
  apk add --no-cache gcc musl-dev
  # musl targets link statically by default, which rules out a cdylib.
  export RUSTFLAGS="-C target-feature=-crt-static"
  # napi defaults arm64 musl to a cross linker; Alpine builds natively.
  export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=gcc
fi
command -v pnpm >/dev/null || corepack enable

pnpm install --frozen-lockfile --ignore-scripts
pnpm --filter "@kokuin/crypto-napi..." build
pnpm --filter @kokuin/crypto-napi run build:native
pnpm --filter @kokuin/crypto-napi run test:native
node scripts/smoke-crypto-napi.mjs
