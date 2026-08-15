# kokuin docs

刻印 -- the stack's identity / auth / keys layer.

- **Stack overview:** https://github.com/TairuFramework/kigu/blob/main/docs/stack.md
- **Conventions & development:** the kigu `conventions` and `development` skills (auto-loaded via the kigu plugin)
- **Architecture:** [agents/architecture.md](./agents/architecture.md)
- **Planning:** [agents/plans/](./agents/plans/)

## Reference

- [Authentication & keys](./reference/auth.md) -- identities, tokens, JWE, keystores.
- [Capabilities & delegation](./reference/capability.md) -- scoped grants, chains, revocation.
- [`did:kokuin:` controllers](./reference/controller.md) -- the profile DID method and its key event log.
- [Security model](./reference/security.md) -- guarantees, assumptions, and what a consumer must do
  for them to hold. **Read this before depending on `did:kokuin:`.**
