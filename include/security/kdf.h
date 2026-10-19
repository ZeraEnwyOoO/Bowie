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
 * BOWIE — SECURITY: KDF
 * ============================================================================
 *
 * Key derivation functions for the security layer.
 *
 * The security layer needs a KDF in two places:
 *
 *   1. Session key derivation: an X25519 shared secret is a
 *      point on a curve, not a uniformly random string. It
 *      must be passed through a KDF before it is used as an
 *      AES key.
 *
 *   2. Subkey separation: a single shared secret may need to
 *      produce more than one key (for example, one key per
 *      direction). HKDF with different info strings gives
 *      independent subkeys from the same secret.
 *
 * The KDF provided here is HKDF-SHA256, as defined by RFC
 * 5869. It is the KDF the security layer uses; a future
 * version may add others without changing this header's
 * shape.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No password hashing. HKDF is not a password hash; a
 *     caller that needs one uses a dedicated KDF.
 *   - No key storage. The KDF produces bytes; the caller
 *     decides where they live.
 *   - No I/O.
 *   - No allocation.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * HKDF is two steps:
 *
 *   extract:  PRK = HMAC-SHA256(salt, IKM)
 *   expand:   OKM = HKDF-Expand(PRK, info, L)
 *
 * The extract step turns the input keying material (the
 * X25519 shared secret) into a pseudorandom key. The expand
 * step turns the pseudorandom key into as many output bytes
 * as the caller needs.
 *
 * The salt is optional. A zero-length salt is allowed and is
 * treated as a string of HashLen zero bytes, as RFC 5869
 * specifies. The security layer uses a zero-length salt for
 * the session key because the shared secret is already
 * high-entropy.
 *
 * The info string is a domain separation tag. Two calls with
 * the same secret but different info strings produce
 * independent keys. The security layer uses the info string
 * to separate subkeys.
 *
 * The output is written to a caller-supplied buffer. The
 * caller must provide at least out_len bytes. A caller that
 * asks for more than BOWIE_KDF_MAX_OUT bytes gets an error;
 * the limit is large enough for any reasonable key and small
 * enough to avoid an accidental large allocation.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <stdint.h>              uint8_t
 *   <stddef.h>              size_t
 *   "bowie/err.h"           bowie_error_t
 * ============================================================================
 */

#ifndef BOWIE_SECURITY_KDF_H
#define BOWIE_SECURITY_KDF_H

#include <stdint.h>
#include <stddef.h>

#include "bowie/err.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ============================================================================
 * CONSTANTS
 * ============================================================================
 */

/*
 * The maximum output length of a single HKDF call, in bytes.
 *
 * 255 * HashLen is the RFC 5869 limit; HashLen is 32 for
 * SHA-256, so the maximum is 8160 bytes. The constant here is
 * smaller because the security layer never needs that much
 * and a smaller bound is easier to reason about.
 */
#define BOWIE_KDF_MAX_OUT 128u

/*
 * The length of the pseudorandom key, in bytes.
 *
 * HKDF-SHA256 produces a 32-byte PRK. The constant is
 * exposed so that a caller that wants to use the PRK
 * directly (rather than only the expanded output) can size
 * its buffer.
 */
#define BOWIE_KDF_SHA256_PRK_LEN 32u

/*
 * ============================================================================
 * HKDF-SHA256
 * ============================================================================
 */

/*
 * Derive out_len bytes from the input keying material.
 *
 * The function performs the full HKDF (extract then
 * expand). The salt and info strings are optional; a NULL
 * pointer with a non-zero length is an error.
 *
 * The caller supplies the output buffer. The function
 * writes exactly out_len bytes on success.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NULL_ARG if ikm, info, or out is NULL
 *   with a non-zero length, or if out_len is non-zero and
 *   out is NULL.
 * Returns BOWIE_ERR_INVAL if out_len is zero or greater
 *   than BOWIE_KDF_MAX_OUT.
 * Returns BOWIE_ERR_CRYPTO if the underlying library
 *   reports a failure.
 */
bowie_error_t bowie_security_kdf_hkdf_sha256(
    const uint8_t *ikm, size_t ikm_len,
    const uint8_t *salt, size_t salt_len,
    const uint8_t *info, size_t info_len,
    uint8_t *out, size_t out_len);

/*
 * ============================================================================
 * END OF SECURITY KDF
 * ============================================================================
 */

#ifdef __cplusplus
}
#endif

#endif /* BOWIE_SECURITY_KDF_H */
