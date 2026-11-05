---
"@kokuin/jwe": minor
---

Pass crypto through UnwrapOptions for signed-envelope verification, including both nested JWE/JWS modes. Default reverification is strict. Wrapping retains identity-owned signing.

All public APIs with two or more arguments now take one flat params object. Options fields sit at the top level.
