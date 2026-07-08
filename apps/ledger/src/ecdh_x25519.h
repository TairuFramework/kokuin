#pragma once

/**
 * Run the X25519 key agreement and respond with the 32-byte shared secret.
 *
 * Called from the key-agreement review UI once the user approves.
 */
void ecdh_approved(void);

/**
 * Discard the stored ephemeral key and respond with a user-rejected status.
 *
 * Called from the key-agreement review UI once the user rejects.
 */
void ecdh_rejected(void);
