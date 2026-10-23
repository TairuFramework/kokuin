---
"@kokuin/controller": minor
---

Breaking (wire): root snapshots carry removed incarnations as tombstones in a new `u` field beside `m`/`d` (a previous verifier ignores it and sees them as absent); `snapshotOf` keeps removed members unless dropped. A reset must not carry `u` (`RESET_HAS_TOMBSTONES`). New `resolveMemberHistoric(did, { did, add, gen })`: resolves an incarnation that was effective in the current generation, including after removal and a later deny of a removed member; refuses another generation, an unknown incarnation and a denied live member (`MEMBER_NOT_HISTORIC`). Controller resolvers return each deny entry raw plus its canonical form, so a `did:peer:4` denied in long form is also denied in short form.
