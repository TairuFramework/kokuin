#pragma once

#include <stdbool.h>

/**
 * Derive the key, sign the accumulated message, and respond with the signature.
 *
 * Called from the sign review UI once the user approves. Returns false when the
 * signature could not be produced, in which case an error status word has
 * already been sent.
 */
bool sign_approved(void);

/**
 * Discard the accumulated message and respond with a user-rejected status.
 *
 * Called from the sign review UI once the user rejects.
 */
void sign_rejected(void);
