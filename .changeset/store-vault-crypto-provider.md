---
"@kokuin/store-vault": minor
---

Pass crypto through records and coordinator parameters. Conflicting nested providers now reject before work. Evidence carries authenticated contentDigest, and payload, metadata and projection checks await validation before persistence.

Use named params objects for public signatures and constructors. Export their named types. Preserve behaviour and update migration references.

All public APIs with two or more arguments now take one flat params object. Options fields sit at the top level.
