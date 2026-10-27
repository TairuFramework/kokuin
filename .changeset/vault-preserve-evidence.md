---
"@kokuin/store-vault": patch
---

`repairFork` no longer rotates only because a `preserve` reissue instruction supplies fresh `consumer` evidence. When the repair is otherwise not needed it returns `not-needed` without writing; when it is needed, the evidence is signed into that entry's reissued output. `contentHLC` overrides and the other reissue actions keep their behaviour.
