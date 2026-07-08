#include <stddef.h>
#include <stdint.h>

#include "os.h"
#include "glyphs.h"
#include "bip32.h"
#include "nbgl_use_case.h"

#include "display.h"
#include "globals.h"
#include "menu.h"
#include "sign_message.h"

// NBGL reads these strings asynchronously while the review is on screen, so the
// buffers must outlive ui_display_sign and cannot live on the stack.
static char g_account[60];
static char g_digest[2 * sizeof(G_context.message_digest) + 1];

static nbgl_contentTagValue_t pairs[2];
static nbgl_contentTagValueList_t pairList;

static void format_hex(const uint8_t *in, size_t in_len, char *out) {
    static const char alphabet[] = "0123456789abcdef";
    for (size_t i = 0; i < in_len; i++) {
        out[2 * i] = alphabet[(in[i] >> 4) & 0x0f];
        out[2 * i + 1] = alphabet[in[i] & 0x0f];
    }
    out[2 * in_len] = '\0';
}

// Invoked once the review reaches a decision: sign on approval, discard on reject.
// Either branch answers the pending APDU before returning to the idle screen.
static void review_choice(bool confirm) {
    if (confirm) {
        sign_approved();
        nbgl_useCaseReviewStatus(STATUS_TYPE_MESSAGE_SIGNED, ui_menu_main);
    } else {
        sign_rejected();
        nbgl_useCaseReviewStatus(STATUS_TYPE_MESSAGE_REJECTED, ui_menu_main);
    }
}

void ui_display_sign(void) {
    if (!bip32_path_format(G_context.bip32_path, G_context.bip32_path_len,
                           g_account, sizeof(g_account))) {
        g_account[0] = '\0';
    }
    format_hex(G_context.message_digest, sizeof(G_context.message_digest), g_digest);

    pairs[0].item = "Account";
    pairs[0].value = g_account;
    pairs[1].item = "Digest";
    pairs[1].value = g_digest;

    pairList.nbMaxLinesForValue = 0;
    pairList.nbPairs = 2;
    pairList.pairs = pairs;
    pairList.wrapping = false;

    nbgl_useCaseReview(TYPE_MESSAGE,
                       &pairList,
                       &ICON_APP_KOKUIN,
                       "Review message",
                       NULL,
                       "Sign message",
                       review_choice);
}
