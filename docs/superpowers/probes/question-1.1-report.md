# Probe report — Question 1.1 (NBGL rewrite)

## Status: DONE

The async consent gate defers SIGN to an NBGL Approve callback. The firmware
builds with `ENABLE_NBGL_FOR_NANO_DEVICES = 1`, renders a review flow (account
path + full SHA-256 digest) that Speculos displays as text events, and a manual
Approve round-trip returns a 64-byte signature + SW `0x9000`. NBGL only; no
BAGL / `ux_flow` anywhere.

## What the question asked

Does the async consent gate defer signing to an Approve callback, rendering a
review (account path + full digest) Speculos can display, with a working manual
Approve round-trip (64-byte signature + SW 0x9000)? — **Yes.**

## Files changed

- `apps/ledger/Makefile` — Two fixes. (1) Replaced the premature top-level
  `include $(BOLOS_SDK)/Makefile.defines` with `include $(BOLOS_SDK)/Makefile.target`
  (matching the SDK's expected layout); the early defines include evaluated
  `USE_NBGL` before it was set, defining `HAVE_BAGL`, which then coexisted with
  `HAVE_NBGL` and pulled the absent `ux_bagl.h`. (2) Added
  `ENABLE_NBGL_FOR_NANO_DEVICES = 1` and `ICON_NANOX`/`ICON_NANOSP` pointing at
  the new app icon.
- `apps/ledger/icons/kokuin_app_14px.gif` (new) — 14x14 app icon; the SDK
  generates the `C_kokuin_app_14px` glyph from it, used for both the review and
  home screens.
- `apps/ledger/src/ui/display.c` — Rewritten for NBGL. Static
  `nbgl_contentTagValue_t pairs[2]` (Account = `bip32_path_format`, Digest = 64
  hex of the SHA-256) into static char buffers, `nbgl_useCaseReview(TYPE_MESSAGE,
  ...)` with a `review_choice(bool)` callback that runs `sign_approved()` /
  `sign_rejected()` then `nbgl_useCaseReviewStatus(..., ui_menu_main)`.
- `apps/ledger/src/ui/display.h` — Adds the `ICON_APP_KOKUIN` glyph macro; keeps
  `void ui_display_sign(void)`.
- `apps/ledger/src/menu.c` — `ui_menu_main()` now renders an NBGL home via
  `nbgl_useCaseHomeAndSettings(APPNAME, &ICON_APP_KOKUIN, ...)` so Speculos boots
  to an idle screen and the post-review status page has somewhere to return to.

Pre-existing (from the prior probe, already in the deferred-handoff shape the
brief describes; kept as-is, verified correct against the new UI):
- `apps/ledger/src/sign_message.c` — non-static `sign_approved()`/`sign_rejected()`;
  both final-chunk paths compute the digest, call `ui_display_sign()`, `return 0`
  with no status word.
- `apps/ledger/src/sign_message.h`, `apps/ledger/src/crypto.{c,h}` (`digest_sha256`),
  `apps/ledger/src/types.h` (`message_digest` field).

Scope honored: SIGN only. ECDH untouched. No `req_type` reset added. The
`P1_CONTINUATION` guard (`req_type != REQ_SIGN_MESSAGE`) is unchanged. No code,
comment, or test references a plan/question/phase number.

## Build output (build service, `docker compose run --rm build`)

The first attempt surfaced a Makefile-ordering bug (kept here as the finding):

```
[CC]   build/nanos2/obj/app/src/app_main.o
In file included from /tmp/build/src/app_main.c:4:
In file included from /opt/nanosplus-secure-sdk/include/os.h:30:
...
/opt/nanosplus-secure-sdk/include/ux.h:21:10: fatal error: 'ux_bagl.h' file not found
   21 | #include "ux_bagl.h"
      |          ^~~~~~~~~~~
1 error generated.
make: *** [.../Makefile.rules_generic:96: build/nanos2/obj/app/src/app_main.o] Error 1
```

Root cause: `ux.h` includes `ux_bagl.h` only under `HAVE_BAGL`. With
`ENABLE_NBGL_FOR_NANO_DEVICES`, `SDK/Makefile.defines` defines `HAVE_NBGL` and
drops `lib_ux` from the include path — but only if `USE_NBGL` is already `1` when
defines runs. The kokuin Makefile included `Makefile.defines` at the top (before
`ENABLE_NBGL_FOR_NANO_DEVICES` / `standard_app` set `USE_NBGL=1`), so that first
pass defined `HAVE_BAGL`; `standard_app`'s later re-include added `HAVE_NBGL` on
top, and the resulting `HAVE_BAGL` include had no `lib_ux/include` on the path.

After switching the top include to `Makefile.target` (mirroring the boilerplate),
the build succeeds. Every app source compiles and the ELF links:

```
[CC]   build/nanos2/gen_src/glyphs.o
[CC]   build/nanos2/obj/app/src/app_main.o
[CC]   build/nanos2/obj/app/src/crypto.o
[CC]   build/nanos2/obj/app/src/dispatcher.o
[CC]   build/nanos2/obj/app/src/ecdh_x25519.o
[CC]   build/nanos2/obj/app/src/get_app_version.o
[CC]   build/nanos2/obj/app/src/get_public_key.o
[CC]   build/nanos2/obj/app/src/menu.o
[CC]   build/nanos2/obj/app/src/sign_message.o
[CC]   build/nanos2/obj/app/src/ui/display.o
...
[CC]   build/nanos2/obj/sdk/lib_nbgl/src/nbgl_use_case.o
[CC]   build/nanos2/obj/sdk/lib_nbgl/src/nbgl_use_case_nanos.o
[CC]   build/nanos2/obj/sdk/lib_ux_nbgl/ux.o
[LINK] build/nanos2/bin/app.elf
[CP] build/nanos2/bin/app.elf => bin/app.elf
```

(The `find: 'glyphs/': No such file or directory` notices are harmless — the SDK
scans an optional per-app `glyphs/` dir that this app does not use; the app-icon
glyph is generated from `icons/kokuin_app_14px.gif`.)

## Manual Approve round-trip (Speculos, `--model nanosp`)

Idle / home screen (NBGL) via `/events?currentscreenonly=true`:

```
{"events": [{"text": "Kokuin", ...}, {"text": "app is ready", ...}]}
```

SIGN APDU sent (single-chunk, `m/44'/876'/0'`, message `"hello"`):
`e003000012038000002c8000036c8000000068656c6c6f`

The APDU call blocks (no status word returned) while the review renders. Screen
text captured page-by-page while navigating with `/button/right`:

```
page 1: {"text": "Review message"}
page 2: {"text": "Account"} {"text": "44'/876'/0'"}
page 3: {"text": "Digest (1/2)"} {"text": "2cf24dba5fb0a30e26"} {"text": "e83b2ac5b9e29e1b16"} {"text": "1e5c1fa7425e730433"}
page 4: {"text": "Digest (2/2)"} {"text": "62938b9824"}
page 5: {"text": "Sign message"}
page 6: {"text": "Reject message"}
```

The four digest fragments concatenate to
`2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824`, which equals
`sha256("hello")` exactly.

Approve driven by navigating to the "Sign message" page and pressing
`/button/both`. Status page then renders:

```
{"events": [{"text": "Message signed"}]}
```

and the UI returns to the "Kokuin / app is ready" home screen. The blocked APDU
call returns:

```
{"data": "c1e70a337312560b6c87b0b197ecbda802f3ec36655a51e79599f06f0e7917b2b8fa026547f4731a32eee2a9a72a8ca8e8bdd359da3b3df8e45fae2c5ccd02099000"}
```

Length check: 132 hex chars = 66 bytes = 64-byte Ed25519 signature + SW `9000`.

## Concerns / surprises

- The real blocker was Makefile include *ordering*, not the NBGL code — the app
  had `include Makefile.defines` at the top where the boilerplate has
  `include Makefile.target`. Anyone toggling NBGL/BAGL flags must keep
  NBGL-affecting settings ahead of the SDK includes that consume them.
- The home screen passes `NULL` for both `settingContents` and `infosList` to
  `nbgl_useCaseHomeAndSettings`. That is safe (the SDK gates the settings button
  on `settingContents != NULL`, so `infosList` is never dereferenced), but there
  is no Version/About page yet. Fine for this probe; revisit if a settings/info
  surface is wanted.
- The app icon is a generic 14x14 glyph copied from the LedgerHQ boilerplate and
  renamed to `kokuin_app_14px.gif`. It is a placeholder, not real branding.
- The existing `speculos.test.ts` sign tests were not run — as the brief notes,
  they will now hang waiting for on-device approval. Build + manual round-trip is
  the bar met here; automating the approval in the test harness is separate work.
- The full-flow round-trip must be scripted in a single shell: a background curl
  to `/apdu` is killed if its shell exits before approval, so send-APDU + drive-
  buttons + read-response have to share one process.
- Speculos was torn down after the run (`docker compose down`). No commit made.
