---
"@kokuin/token": patch
---

The default EdDSA and ES256 verifiers remember positive results: a signature already verified over byte-equal message bytes, under the same algorithm and public key, is answered without re-running the curve math. Process-wide LRU of 8192 entries; messages over 16 KiB are never remembered; failures and thrown errors are never remembered. A verifier passed through the `verifiers` option is called as given, every time.
