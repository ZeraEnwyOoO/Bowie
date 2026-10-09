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
 * BOWIE — KEYPAIR
 * ============================================================================
 *
 * X25519 key agreement.
 *
 * This header declares the key agreement functions Bowie uses.
 * The implementation is backed by OpenSSL.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No signing. Ed25519 signatures are in sign.h.
 *   - No encryption. Symmetric encryption is in cipher.h.
 *   - No certificate parsing. Bowie does not use X.509.
 *   - No key storage. A caller that needs persistence must
 *     provide it.
 *   - No streaming API. Key agreement is a single operation on
 *     two 32-byte keys.
 *   - No allocation. Every function writes to a caller-supplied
 *     output buffer.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * X25519 is the key agreement algorithm. It is used for:
 *
 *   - Session key establishment: two peers exchange public
 *     keys and derive a shared secret. The secret is used to
 *     derive a symmetric key for the session.
 *
 *   - Forward secrecy: a fresh X25519 keypair per session
 *     means a compromise of one session's key does not
 *     compromise another.
 *
 * X25519 keys are 32 bytes. A public key is 32 bytes; a
 * private key is 32 bytes; the shared secret is 32 bytes.
 *
 * The shared secret is not a symmetric key. It is a
 * high-entropy point on the curve. A caller that needs a
 * symmetric key must pass the shared secret through a KDF.
 * The recommended KDF for a session is HKDF-SHA256; a caller
 * that does not have HKDF can use HMAC-SHA256 (in hash.h) as a
 * simple extract-then-expand.
 *
 * The private key is generated from the platform entropy
 * source. The generation function is the one in rand.h; this
 * module wraps it.
 *
 * Ed25519 and X25519 use different curve representations. Do
 * not reuse an Ed25519 key for X25519 or vice versa. The two
 * are not interchangeable.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <stdint.h>                    uint8_t
 *   <stddef.h>                    size_t
 *   "bowie/err.h"                 bowie_error_t
 *   <openssl/evp.h>               EVP_PKEY, EVP_PKEY_CTX
 * ============================================================================
 */

#ifndef BOWIE_CRYPTO_KEYPAIR_H
#define BOWIE_CRYPTO_KEYPAIR_H

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

#define BOWIE_KEYPAIR_PUBLIC_LEN  32
#define BOWIE_KEYPAIR_PRIVATE_LEN 32
#define BOWIE_KEYPAIR_SHARED_LEN  32

/*
 * ============================================================================
 * TYPES
 * ============================================================================
 *
 * Fixed-size value types. A key or a shared secret can be
 * copied and compared without allocation.
 */

typedef struct bowie_keypair_public {
    uint8_t bytes[BOWIE_KEYPAIR_PUBLIC_LEN];
} bowie_keypair_public_t;

typedef struct bowie_keypair_private {
    uint8_t bytes[BOWIE_KEYPAIR_PRIVATE_LEN];
} bowie_keypair_private_t;

typedef struct bowie_keypair_shared {
    uint8_t bytes[BOWIE_KEYPAIR_SHARED_LEN];
} bowie_keypair_shared_t;

/*
 * ============================================================================
 * GENERATION
 * ============================================================================
 */

/*
 * Generate an X25519 keypair.
 *
 * The private key is generated from the platform entropy
 * source. The public key is derived from the private key.
 *
 * On success, both keys are written through the out pointers.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NULL_ARG if either out pointer is NULL.
 * Returns BOWIE_ERR_CRYPTO if the underlying library or the
 *   entropy source reports a failure.
 */
bowie_error_t bowie_keypair_x25519_generate(
    bowie_keypair_public_t *out_public,
    bowie_keypair_private_t *out_private);

/*
 * Derive the public key from an X25519 private key.
 *
 * The private key is 32 bytes. The public key is the result
 * of the X25519 scalar multiplication with the curve's base
 * point.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NULL_ARG if either pointer is NULL.
 * Returns BOWIE_ERR_CRYPTO if the underlying library reports a
 *   failure.
 */
bowie_error_t bowie_keypair_x25519_public_from_private(
    const bowie_keypair_private_t *private_key,
    bowie_keypair_public_t *out);

/*
 * ============================================================================
 * AGREEMENT
 * ============================================================================
 */

/*
 * Compute the shared secret between a local private key and a
 * remote public key.
 *
 * The shared secret is 32 bytes. It is not a symmetric key;
 * a caller that needs one must pass the secret through a KDF.
 *
 * The operation is symmetric: the secret derived from
 * (local_private, remote_public) equals the secret derived
 * from (remote_private, local_public).
 *
 * The function does not check that the remote public key is on
 * the curve. A caller that needs that check must do it before
 * the call.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NULL_ARG if any pointer is NULL.
 * Returns BOWIE_ERR_CRYPTO if the underlying library reports a
 *   failure. A common failure is a low-order public key that
 *   yields the all-zero shared secret.
 */
bowie_error_t bowie_keypair_x25519_shared(
    const bowie_keypair_private_t *local_private,
    const bowie_keypair_public_t *remote_public,
    bowie_keypair_shared_t *out);

#ifdef __cplusplus
}
#endif

#endif /* BOWIE_CRYPTO_KEYPAIR_H */
