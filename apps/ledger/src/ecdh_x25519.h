#pragma once

#include <stdbool.h>

/**
 * Run the X25519 key agreement and respond with the 32-byte shared secret.
 *
 * Called from the key-agreement review UI once the user approves. Returns false
 * when the shared secret could not be derived, in which case an error status
 * word has already been sent.
 */
bool ecdh_approved(void);

/**
 * Discard the stored ephemeral key and respond with a user-rejected status.
 *
 * Called from the key-agreement review UI once the user rejects.
 */
void ecdh_rejected(void);
