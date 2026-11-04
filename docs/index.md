# kokuin docs

刻印 -- the stack's identity / auth / keys layer.
- **Stack overview:** https://github.com/TairuFramework/kigu/blob/main/docs/stack.md
- **Conventions & development:** the kigu `conventions` and `development` skills (auto-loaded via the kigu plugin)
- **Architecture:** [agents/architecture.md](./agents/architecture.md)
- **Planning:** [agents/plans/](./agents/plans/)

## Reference

- [Authentication & keys](./reference/auth.md) -- identities, tokens, JWE, keystores.
- [Crypto providers and adoption](./reference/crypto-provider.md) -- portable noble, Node and explicit native providers, provider selection, Promise migration and strict verification.
- [Node crypto benchmark gate](./reference/crypto-node-benchmark.md) -- how `@kokuin/crypto-napi` routes are measured and chosen.
- [Capabilities & delegation](./reference/capability.md) -- scoped grants, chains, revocation.
- [`did:kokuin:` controllers](./reference/controller.md) -- the profile DID method and its key event log.
- [Vault](./reference/vault.md) -- content-key crypto, signed vault records, storage and coordinators.
- [Stores](./reference/stores.md) -- Hozon-backed persistence for controller logs, delegation tokens and
  revocations; the `hlc` contract, purge scheduling and the revocation checker.
- [Security model](./reference/security.md) -- guarantees, assumptions, and what a consumer must do
  for them to hold. **Read this before depending on `did:kokuin:`.**
