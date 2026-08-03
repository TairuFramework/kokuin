# A `did:peer:4` signer cannot produce a verifiable revocation record

**Status:** next
**Severity:** security — fail-open, latent
**Origin:** found from kubun while fixing a delegation-revocation fail-open (`kubun/docs/superpowers/specs/2026-08-03-delegation-revocation-comember-binding-design.md`, question 2.4). Confirmed empirically in kubun's suite, not inferred.

## What happens

`createRevocationRecord` produces a token whose `iss` a recipient cannot resolve, so every recipient drops it at signature verification. A `did:peer:4` grantor can therefore revoke nothing: the revocation binds on the grantor's own device, which stores its self-minted row without verifying it, and nowhere else.

That is strictly worse than the delegation fail-open kubun is currently fixing, which at least bound on the grantor *and* the delegate.

## Why

Two behaviours that are individually reasonable compose badly.

`createRevocationRecord` signs claims that carry no `aud`:

```ts
// packages/capability/src/revocation.ts:75-81
export async function createRevocationRecord(
  signer: SigningIdentity,
  jti: string,
): Promise<RevocationRecord> {
  return (await signer.signToken({ jti, rev: true, iat: now() })) as RevocationRecord
}
```

`pickIss` embeds the long form only for the first token to a given audience, and falls back to the short form when the payload names no audience at all:

```ts
// packages/token/src/identity.ts, buildIdentity → pickIss
if (!isPeer) return id
if (embedLongForm === true) return longForm
if (embedLongForm === false) return id
const aud = payload.aud
if (typeof aud !== 'string') return id   // ← revocation records land here
const normalizedAud = normalizeDID(aud)
if (sentTo.has(normalizedAud)) return id
sentTo.add(normalizedAud)
return longForm
```

So a peer:4 revocation record always carries the **short** form. A short-form `did:peer:4` is a hash of the DID document and cannot be resolved without that document. The recipient has no way to obtain it: the long form is what seeds a recipient's DID cache, and a revocation record never carries one.

Observed on the recipient side: `Unknown DID: did:peer:4zQma7t…`.

The `sentTo` cache does not rescue it either. It is per-`aud`, and a revocation has no `aud` — so the "already sent them the long form once" path is never even consulted, regardless of how many other tokens the same signer has sent.

## Scope of the impact

Any protocol message signed with claims that carry no `aud` has the same shape. Revocation records are the case found, because kubun consumes them on a security-critical path, but the rule is general: **a peer:4 signer's audience-less token is unverifiable by anyone who has not already cached its document.**

## Not currently live in kubun

Kubun has no multi-key identity construction outside test fixtures — every production path is `randomIdentity()` or `createFullIdentity(privateKey)`, a single Ed25519 signing key, which `chooseMethod` resolves to `did:key`. `normalizeDID` is the identity function for `did:key`, and no peer:4 DID reaches a kubun revocation today.

It is a trap door rather than a live defect: `chooseMethod` selects `peer:4` automatically for any identity carrying more than one key or a non-signing key — which is the natural shape once a KEM key sits on the identity for key agreement. The first such identity would silently make revocation broadcast-unverifiable, with no error at the point of revocation and a debug-level skip on every recipient.

## Possible directions

Not a recommendation — the trade-off is kokuin's to make.

- **Default `embedLongForm: true` in `createRevocationRecord`.** Smallest change, and revocation records are rare and small, so the size cost is negligible. Leaves the general audience-less case open.
- **Make `pickIss` embed the long form whenever the payload has no `aud`.** Fixes the general case. Costs long-form `iss` on every audience-less token, which may be a size regression on hot paths.
- **Let the recipient resolve a short form from a document it already holds**, keyed by hash. Only helps when the recipient has seen the signer before, which for a group co-member is likely but not guaranteed.

## How to reproduce

Sign a revocation record with a `did:peer:4` identity and verify it from a second process with no prior DID cache:

```ts
const signer = await createIdentity({ didMethod: 'peer:4', keys: [...] })
const record = await createRevocationRecord(signer, 'some-jti')
await verifyToken(record)   // throws: Unknown DID: did:peer:4zQma7t…
```

Contrast with the same identity signing a payload that carries an `aud`, whose first token to that audience embeds the long form and verifies.
