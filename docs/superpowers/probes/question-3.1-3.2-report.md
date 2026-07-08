# Probe report — Speculos auto-approval + reject/stale tests

Status: **DONE**

Both deliverables landed in `tests/ledger/test/speculos.test.ts`. The full Speculos
suite now runs unattended (auto-approving the NBGL review), and three negative tests
were added. No firmware was changed; this is TypeScript test-harness work only.

## How auto-approval was achieved (the working automation approach)

The NBGL review on the Nano S+ paginates each info field onto its own page, so a
single "confirm" button rule is not enough — every info page must be advanced past
before the confirm/reject page is reachable. The working mechanism is a Speculos
`POST /automation` ruleset whose rules match the **on-screen page titles** and fire
button presses:

- Button `1` = left key, button `2` = right key. An action is a
  `[event, button, pressed]` tuple. A page advance is a press-and-release of the
  right key `[["button",2,true],["button",2,false]]`; a confirm/reject is a
  simultaneous both-key press
  `[["button",1,true],["button",2,true],["button",1,false],["button",2,false]]`.
- Rules use `regexp` (not `text`) match. This matters for the **ECDH title**, which
  wraps onto two device events — `"Review key "` and `"agreement"` — so the ruleset
  matches the first line `"Review key"` rather than the full `"Review key agreement"`.
  (The initial attempt with `text`/full-string `"Review key agreement"` matched
  neither event and stalled the review — that was the one empirical dead end;
  switching to `regexp: "Review key"` fixed it.)

Empirically-determined page sequences (walked against the running emulator):

- SIGN: `Review message` → `Account` → `Digest (1/2)` → `Digest (2/2)` →
  **`Sign message`** (confirm) → `Reject message` (reject).
- ECDH: `Review key ` / `agreement` → `Account` → `Peer key` →
  **`Agree key`** (confirm) → `Reject operation` (reject).

**APPROVE_RULES**: advance on every info-page pattern
(`Review message`, `Review key`, `Account`, `Digest`, `Peer key`), then both-press on
`Sign message` and `Agree key`.

**REJECT_RULES**: advance on every info-page pattern **and** on the confirm pages
(`Sign message`, `Agree key`) to step past them, then both-press on `Reject message`
and `Reject operation`.

A top-level `beforeEach` installs `APPROVE_RULES` before every test, so the default
flow is unattended and any reject test that overrides the ruleset (within its own body)
is automatically restored to approve for whatever test runs next — robust to ordering.

The home/idle screen (`Kokuin` / `app is ready`) and status screens
(`Message signed`, `Operation rejected`, …) match no rule, so automation never fires on
them.

## New negative tests (in `Ledger app: review rejection and guards`)

A non-throwing `exchangeAPDU(apduHex)` helper returns `{ data, sw }` (the existing
transport still throws on non-`0x9000`; the reject/stale cases need the raw status
word). APDUs are built with `CLA` / `INS` / `encodeDerivationPath` from
`@kokuin/ledger-device`.

1. **SIGN reject → `0x6985`**: installs `REJECT_RULES`, posts a single-chunk
   `SIGN_MESSAGE`, asserts `sw === 0x6985` and empty data.
2. **ECDH reject → `0x6985`**: installs `REJECT_RULES`, posts `ECDH_X25519` with a
   random x25519 ephemeral pubkey, asserts `sw === 0x6985` and empty data.
3. **Stale continuation → `0x6A80`**: completes an approved single-chunk signature
   (asserts `0x9000` + 64-byte signature, which clears `req_type`), then posts the
   1-byte continuation `e00380000141` (`P1=0x80`, `Lc=01`, `data=0x41`) and asserts
   `sw === 0x6A80`. A bare `Lc=00` continuation was deliberately avoided — the
   dispatcher's length guard rejects that earlier as `0x6700`.

## Verify — actual output

### `./tests/ledger/test-speculos.sh --build`

```
 RUN  v4.1.10 /Users/paul/dev/yulsi/kokuin/tests/ledger

 Test Files  1 passed (1)
      Tests  15 passed (15)
   Start at  22:42:49
   Duration  41.25s
All tests passed.
```

Per-test listing (clean re-run against a freshly-built ELF, `--reporter=verbose`):

```
 ✓ Ledger app: APDU protocol > GET_APP_VERSION returns 3 bytes
 ✓ Ledger app: APDU protocol > GET_PUBLIC_KEY returns 32-byte Ed25519 public key
 ✓ Ledger app: APDU protocol > GET_PUBLIC_KEY is deterministic for same path
 ✓ Ledger app: APDU protocol > GET_PUBLIC_KEY returns different keys for different paths
 ✓ Ledger app: review rejection and guards > SIGN_MESSAGE returns 0x6985 when the review is rejected
 ✓ Ledger app: review rejection and guards > ECDH_X25519 returns 0x6985 when the review is rejected
 ✓ Ledger app: review rejection and guards > SIGN_MESSAGE continuation after a completed signature returns 0x6A80
 ✓ Ledger app + ledger-identity integration > provideIdentity() returns FullIdentity with valid DID
 ✓ Ledger app + ledger-identity integration > signToken() produces verifiable JWT
 ✓ Ledger app + ledger-identity integration > agreeKey() returns 32-byte shared secret
 ✓ Ledger app + ledger-identity integration > decrypt() decrypts JWE encrypted to ledger identity
 ✓ Ledger app + hd-keystore cross-compatibility > same mnemonic produces same DID
 ✓ Ledger app + hd-keystore cross-compatibility > tokens from both sources are verifiable and share same issuer
 ✓ Ledger app + hd-keystore cross-compatibility > ECDH produces same shared secret from both sources
 ✓ Ledger app + hd-keystore cross-compatibility > JWE encrypted by HD identity is decryptable by Ledger identity
 Test Files  1 passed (1)
      Tests  15 passed (15)
```

### `pnpm exec biome check tests/ledger`

```
Lint: No issues found
```

### `pnpm exec tsc -p tests/ledger/tsconfig.json --noEmit`

```
TypeScript: No errors found
```

## Concerns

- The `test-speculos.sh --build` run reused an already-running Speculos container from
  the exploratory phase; a subsequent clean run (container torn down, freshly-built ELF
  loaded) also passed 15/15, so this had no effect on the result.
- Auto-approval depends on NBGL page-title strings (`Review message`, `Account`,
  `Digest`, `Peer key`, `Sign message`, `Agree key`, `Reject message`,
  `Reject operation`) and on the ECDH title wrapping such that `Review key` matches its
  first line. Any firmware wording change to these screens would require updating
  `REVIEW_PAGE_PATTERNS` / the confirm/reject patterns. This is inherent to text-driven
  emulator automation.
