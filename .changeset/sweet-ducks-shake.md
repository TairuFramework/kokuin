---
"@kokuin/token": minor
---

Management member resolution: `DIDMethodResolver` gains an optional `resolveMember(subject, { did, add, gen })` answering `{ key, lease }` for a member of a subject's management tier (its absence fails closed), with the `MemberQuery` and `ResolvedMember` types; `signingKeysOf(did)` reads the signing keys a `did:key` or long-form `did:peer:4` carries in its identifier. Additive: no existing signature changes, but resolver wrappers must forward `resolveMember` like every other optional member.
