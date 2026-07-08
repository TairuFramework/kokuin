#pragma once

/**
 * Derive the key, sign the accumulated message, and respond with the signature.
 *
 * Called from the sign review UI once the user approves.
 */
void sign_approved(void);

/**
 * Discard the accumulated message and respond with a user-rejected status.
 *
 * Called from the sign review UI once the user rejects.
 */
void sign_rejected(void);
