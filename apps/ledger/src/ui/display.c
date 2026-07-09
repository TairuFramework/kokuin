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
#include "ecdh_x25519.h"

// NBGL reads these strings asynchronously while the review is on screen, so the
// buffers must outlive ui_display_sign / ui_display_ecdh and cannot live on the
// stack. A single review runs at a time, so the account and pair buffers are
// shared across the sign and key-agreement flows.
static char g_account[64];
static char g_digest[2 * sizeof(G_context.message_digest) + 1];
static char g_peer_key[2 * sizeof(G_context.peer_key_digest) + 1];

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
// Every branch answers the pending APDU before returning to the idle screen, and
// the status screen reports the outcome the host was given.
static void review_choice(bool confirm) {
    if (!confirm) {
        sign_rejected();
        nbgl_useCaseReviewStatus(STATUS_TYPE_MESSAGE_REJECTED, ui_menu_main);
    } else if (sign_approved()) {
        nbgl_useCaseReviewStatus(STATUS_TYPE_MESSAGE_SIGNED, ui_menu_main);
    } else {
        nbgl_useCaseStatus("Signing failed", false, ui_menu_main);
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

// Invoked once the key-agreement review reaches a decision: run the ECDH on
// approval, discard the ephemeral key on reject. Every branch answers the
// pending APDU before returning to the idle screen, and the status screen
// reports the outcome the host was given. The built-in review statuses only
// speak of signed transactions, messages and operations, so a key agreement
// states its own outcome.
static void agreement_choice(bool confirm) {
    if (!confirm) {
        ecdh_rejected();
        nbgl_useCaseStatus("Key agreement rejected", false, ui_menu_main);
    } else if (ecdh_approved()) {
        nbgl_useCaseStatus("Key agreed", true, ui_menu_main);
    } else {
        nbgl_useCaseStatus("Key agreement failed", false, ui_menu_main);
    }
}

void ui_display_ecdh(void) {
    if (!bip32_path_format(G_context.bip32_path, G_context.bip32_path_len,
                           g_account, sizeof(g_account))) {
        g_account[0] = '\0';
    }
    format_hex(G_context.peer_key_digest, sizeof(G_context.peer_key_digest), g_peer_key);

    pairs[0].item = "Account";
    pairs[0].value = g_account;
    pairs[1].item = "Peer key";
    pairs[1].value = g_peer_key;

    pairList.nbMaxLinesForValue = 0;
    pairList.nbPairs = 2;
    pairList.pairs = pairs;
    pairList.wrapping = false;

    nbgl_useCaseReview(TYPE_OPERATION,
                       &pairList,
                       &ICON_APP_KOKUIN,
                       "Review key agreement",
                       NULL,
                       "Agree key",
                       agreement_choice);
}
