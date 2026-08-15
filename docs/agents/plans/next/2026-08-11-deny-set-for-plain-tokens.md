# The deny set is enforced for capabilities only

**Priority:** high — a revoked device still authenticates by ordinary token.
**Origin:** the `did:kokuin:` controller work, 2026-08-11, raised in review and accepted as a named
limit rather than fixed. See `completed/2026-08-11-controller-key-events.complete.md`.

## The gap

A `revoke` event adds a DID to the profile's deny set. `@kokuin/capability` enforces that: a
capability whose `aud` has been denied is rejected, at the leaf and at every intermediate link of a
delegation chain. Reproduced end to end during development, with the control that a non-denied
audience still verifies against the same log.

`verifyToken` consults the deny set for one thing only, and it is not this one. A `rev` naming a
**key** (`#<multibase key>`) is enforced inside the resolver, so a token signed by a revoked key of
the profile itself is refused there — but that is the profile denying its own signing key, not the
profile denying a device. A device the profile has revoked signs an ordinary token with its **own**
key, resolved through its own method (`did:key`, `did:peer:4`), which knows nothing about this
profile's deny set. So a consumer authenticating a device by plain token — rather than by presenting
a capability — still gets no denial from revocation at all, with the deny set sitting right there in
the resolved state of a profile nothing thought to ask about.

This matches the design's own wording, which says only that no *capability* whose `aud` is that DID
is valid from the revoke position onward. Whether that wording is what was actually wanted is the
open question.

## Why it was not simply fixed

`verifyToken` has no `sub`. It resolves an issuer and checks a signature; it is not given the
profile whose deny set would have to be consulted, and a token does not carry one. So the check
cannot be added where the gap is — it needs either a new input at the call site or a separate
`isDenied(state, did)` helper that callers apply themselves.

There is also no `isDenied` helper today. The deny set reaches consumers only through
`DIDMethodResolver.resolveDenySet`, which is the shape `@kokuin/capability` needed.

One consequence of the key-denial work to carry into any helper: the set is **heterogeneous**. It
holds DIDs and `#<multibase key>` fragments in one collection, deliberately, so that a wrapper
cannot forward one rule and drop the other. The two forms cannot collide, so membership tests stay
exact — but a helper that *enumerates* the set as a list of revoked devices would be wrong.

## Work

1. Decide whether device authentication by plain token is a path that must honour revocation, or
   whether every authenticating path should be required to present a capability. The second is a
   coherent answer and may be the right one — but it is currently true by accident rather than by
   design, and nothing says so.
2. If revocation must reach plain tokens: add the helper, and give `verifyToken` (or a wrapper) the
   subject it needs. Fail closed when the deny set cannot be resolved — the same rule the rest of
   this work settled on.
3. Either way, say so in the auth documentation. A reader today would reasonably assume a revoked
   device cannot authenticate.

## Related, decided already

Revoking a *self-issued* invocation has no effect: `checkCapability` returns early on the
`iss === sub` branch, so the `jti` revocation record is never consulted. The audience check does run
on that branch, so a revoked *device* is caught there — but a revoked *capability* on a self-issued
invocation is not. That was left untouched deliberately and is worth resolving alongside this.
