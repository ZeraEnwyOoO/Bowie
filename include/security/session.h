 /*
 * Bowie — P2P Internet Sharing Tool (Repo: bowie)
 * Copyright (C) 2026 ASBM Team
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

/*
 * ============================================================================
 * BOWIE — SECURITY: SESSION
 * ============================================================================
 *
 * Session key derivation and symmetric encryption.
 *
 * A session is an authenticated, encrypted channel between two
 * peers. It is established with a key agreement (X25519) and
 * used with a symmetric cipher (AES-256-GCM).
 *
 * The session layer is independent of the crypto/ layer: it
 * calls OpenSSL directly for HKDF and AES-GCM. The crypto/
 * layer is a general-purpose library; the security/ layer is
 * the policy that decides how the library is used.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No key agreement. The X25519 exchange is done by the
 *     caller, which passes the shared secret to
 *     bowie_session_new(). This layer consumes the secret.
 *   - No identity. The proof of ownership is in ownership.h.
 *   - No grant verification. That is a permission concern.
 *   - No key storage. The session key lives in the handle and
 *     is wiped on close.
 *   - No nonce management across rekeys. A caller that wants
 *     to rekey must create a new session.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * The session key is derived from the X25519 shared secret
 * with HKDF-SHA256. The shared secret is not used directly as
 * an AES key: it is a point on the curve, not a uniformly
 * random string. HKDF extracts a uniform key and expands it to
 * the length the cipher needs.
 *
 * The nonce for AES-256-GCM is 12 bytes. It must be unique
 * for every message encrypted with the same key. The session
 * maintains a 64-bit counter and builds the nonce as:
 *
 *     [ 4 bytes: zero ] [ 8 bytes: counter, big-endian ]
 *
 * This gives 2^64 messages per session, which is far beyond
 * any realistic session lifetime. The counter is not
 * transmitted; both peers derive the same nonce from the same
 * message order. If a message is lost, the counter is still
 * advanced so that the two peers stay in sync.
 *
 * The handle is opaque. The caller owns it, never sees its
 * layout, and frees it with bowie_session_free().
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <stdint.h>              uint8_t, uint32_t, uint64_t
 *   <stddef.h>              size_t
 *   "bowie/types.h"         bowie_span_t, bowie_session_t,
 *                           bowie_session_id_t
 *   "bowie/err.h"           bowie_error_t
 * ============================================================================
 */

#ifndef BOWIE_SECURITY_SESSION_H
#define BOWIE_SECURITY_SESSION_H
#define BOWIE_SESSION_KEY_LEN 32u

#include <stdint.h>
#include <stddef.h>

#include "bowie/types.h"
#include "bowie/err.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ============================================================================
 * LIFECYCLE
 * ============================================================================
 */

/*
 * Create a session from a shared secret.
 *
 * The shared secret is the output of X25519 (32 bytes). The
 * session layer runs HKDF-SHA256 on it to produce the
 * symmetric key, then wipes the secret.
 *
 * The session ID is a caller-supplied nonce. It is not used
 * for cryptography; it is used for logging and for
 * correlating messages. An all-zero ID is rejected.
 *
 * On success, *out points to the new session handle.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NULL_ARG if out or secret is NULL.
 * Returns BOWIE_ERR_INVAL if the session ID is all-zero.
 * Returns BOWIE_ERR_CRYPTO if HKDF fails.
 */
bowie_error_t bowie_session_new(const uint8_t *shared_secret,
                                size_t shared_secret_len,
                                const bowie_session_id_t *session_id,
                                bowie_session_t **out);
/*
 * Create a session from a pre-derived symmetric key.
 *
 * This is the "advanced" form of bowie_session_new(). The
 * caller has already derived the session key with a KDF and
 * passes the key bytes directly. The session layer does not
 * run a KDF on the key; it copies it and uses it as the
 * AES-256-GCM key.
 *
 * The key must be exactly BOWIE_SESSION_KEY_LEN bytes. A
 * key of any other length is rejected. The caller is
 * responsible for the KDF's domain separation; the session
 * layer does not add an info string of its own.
 *
 * The session ID is a caller-supplied nonce. It is not used
 * for cryptography; it is used for logging and for
 * correlating messages. An all-zero ID is rejected.
 *
 * On success, *out points to the new session handle.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NULL_ARG if out, key, or session_id is
 *   NULL.
 * Returns BOWIE_ERR_INVAL if the session ID is all-zero or
 *   if the key length is not BOWIE_SESSION_KEY_LEN.
 * Returns BOWIE_ERR_NOMEM if allocation fails.
 */
bowie_error_t bowie_session_new_from_key(
    const uint8_t *key, size_t key_len,
    const bowie_session_id_t *session_id,
    bowie_session_t **out);
/*
 * Free a session.
 *
 * The session key is wiped before the handle is freed.
 * Passing NULL is a no-op.
 */
void bowie_session_free(bowie_session_t *session);

/*
 * ============================================================================
 * QUERY
 * ============================================================================
 */

/*
 * Return the session ID.
 *
 * The ID is copied into the caller's struct. Passing NULL for
 * the session is a no-op.
 */
void bowie_session_get_id(const bowie_session_t *session,
                          bowie_session_id_t *out);

/*
 * ============================================================================
 * ENCRYPT
 * ============================================================================
 *
 * Encrypt a plaintext into a caller-supplied buffer.
 *
 * The output is the ciphertext followed by a 16-byte AEAD
 * tag. The caller must allocate at least
 * plaintext_len + 16 bytes.
 *
 * The nonce is derived from an internal counter that
 * advances on every call. The caller must not skip a call:
 * both peers must encrypt the same number of messages in the
 * same order, or their nonces will diverge.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NULL_ARG if any required pointer is NULL.
 * Returns BOWIE_ERR_TOO_SMALL if the output buffer is too
 *   small.
 * Returns BOWIE_ERR_CRYPTO if the underlying cipher fails.
 */
bowie_error_t bowie_session_encrypt(bowie_session_t *session,
                                    const void *plaintext,
                                    size_t plaintext_len,
                                    uint8_t *out,
                                    size_t out_cap,
                                    size_t *out_len);

/*
 * ============================================================================
 * DECRYPT
 * ============================================================================
 *
 * Decrypt a ciphertext produced by bowie_session_encrypt().
 *
 * The input is the ciphertext followed by a 16-byte AEAD
 * tag. The caller passes the total length.
 *
 * The tag is verified before the plaintext is written to the
 * output buffer. If verification fails, the output buffer is
 * not modified.
 *
 * The nonce is derived from an internal counter that
 * advances on every call. The caller must not skip a call:
 * both peers must decrypt the same number of messages in the
 * same order, or their nonces will diverge.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NULL_ARG if any required pointer is NULL.
 * Returns BOWIE_ERR_TOO_SMALL if the output buffer is too
 *   small.
 * Returns BOWIE_ERR_CRYPTO if the tag verification fails or
 *   the cipher fails.
 */
bowie_error_t bowie_session_decrypt(bowie_session_t *session,
                                    const void *ciphertext,
                                    size_t ciphertext_len,
                                    uint8_t *out,
                                    size_t out_cap,
                                    size_t *out_len);

/*
 * ============================================================================
 * END OF SECURITY SESSION
 * ============================================================================
 */

#ifdef __cplusplus
}
#endif

#endif /* BOWIE_SECURITY_SESSION_H */
