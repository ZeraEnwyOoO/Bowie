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
 * BOWIE — HASH
 * ============================================================================
 *
 * Cryptographic hash functions.
 *
 * This header declares the hash functions Bowie uses. The
 * implementation is backed by OpenSSL.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No password hashing. Bowie does not store passwords. A
 *     caller that needs password hashing must use a dedicated
 *     KDF, not a raw hash.
 *   - No key derivation. HMAC is provided; a full KDF (HKDF,
 *     PBKDF2) is not.
 *   - No streaming API. Every function hashes a complete
 *     buffer. A caller that needs to hash a stream must buffer
 *     it.
 *   - No allocation. Every function writes to a caller-supplied
 *     output buffer.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * The hash functions are grouped by algorithm:
 *
 *   - SHA-256 is the default. It is used for content hashing,
 *     integrity checks, and the peer ID derivation when a
 *     256-bit hash is needed.
 *
 *   - SHA-1 is provided for DHT compatibility. The DHT
 *     identifier space is 160 bits, which is the SHA-1 output
 *     size. A new protocol should not use SHA-1 for security;
 *     it is provided because the DHT identifier space requires
 *     160 bits.
 *
 *   - MD5 is provided for compatibility with legacy formats. It
 *     is not a secure hash. A new protocol should not use MD5.
 *
 *   - HMAC-SHA256 is provided for message authentication. The
 *     key is a caller-supplied byte string.
 *
 * The output types are fixed-size structs. A hash is a value
 * that can be copied and compared without allocation. The
 * struct layout is a byte array; a caller can read the bytes
 * directly.
 *
 * Every hash function returns BOWIE_OK on success. The only
 * failure mode is a NULL argument; the underlying OpenSSL
 * implementation does not fail for a valid input.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <stdint.h>                    uint8_t
 *   <stddef.h>                    size_t
 *   "bowie/err.h"                 bowie_error_t
 *   <openssl/sha.h>               SHA-1, SHA-256
 *   <openssl/md5.h>               MD5
 *   <openssl/hmac.h>              HMAC
 * ============================================================================
 */

#ifndef BOWIE_CRYPTO_HASH_H
#define BOWIE_CRYPTO_HASH_H

#include <stdint.h>
#include <stddef.h>

#include "bowie/err.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ============================================================================
 * HASH SIZES
 * ============================================================================
 */

#define BOWIE_HASH_SHA256_LEN 32
#define BOWIE_HASH_SHA1_LEN   20
#define BOWIE_HASH_MD5_LEN    16

/*
 * ============================================================================
 * HASH TYPES
 * ============================================================================
 *
 * Fixed-size value types. A hash can be copied and compared
 * without allocation.
 */

typedef struct bowie_hash_sha256 {
    uint8_t bytes[BOWIE_HASH_SHA256_LEN];
} bowie_hash_sha256_t;

typedef struct bowie_hash_sha1 {
    uint8_t bytes[BOWIE_HASH_SHA1_LEN];
} bowie_hash_sha1_t;

typedef struct bowie_hash_md5 {
    uint8_t bytes[BOWIE_HASH_MD5_LEN];
} bowie_hash_md5_t;

/*
 * ============================================================================
 * SHA-256
 * ============================================================================
 */

/*
 * Compute the SHA-256 hash of a buffer.
 *
 * On success, the 32-byte hash is written through out.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NULL_ARG if data or out is NULL.
 *   A data pointer with len == 0 is allowed.
 * Returns BOWIE_ERR_CRYPTO if the underlying library reports a
 *   failure. In practice this is not expected.
 */
bowie_error_t bowie_hash_sha256(const void *data, size_t len,
                                 bowie_hash_sha256_t *out);

/*
 * ============================================================================
 * SHA-1
 * ============================================================================
 */

/*
 * Compute the SHA-1 hash of a buffer.
 *
 * On success, the 20-byte hash is written through out.
 *
 * Same return values as bowie_hash_sha256.
 *
 * SHA-1 is provided for DHT compatibility. A new protocol
 * should not use SHA-1 for security.
 */
bowie_error_t bowie_hash_sha1(const void *data, size_t len,
                               bowie_hash_sha1_t *out);

/*
 * ============================================================================
 * MD5
 * ============================================================================
 */

/*
 * Compute the MD5 hash of a buffer.
 *
 * On success, the 16-byte hash is written through out.
 *
 * Same return values as bowie_hash_sha256.
 *
 * MD5 is provided for compatibility with legacy formats. It is
 * not a secure hash.
 */
bowie_error_t bowie_hash_md5(const void *data, size_t len,
                              bowie_hash_md5_t *out);

/*
 * ============================================================================
 * HMAC-SHA256
 * ============================================================================
 */

/*
 * Compute the HMAC-SHA256 of a buffer with a key.
 *
 * On success, the 32-byte MAC is written through out.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NULL_ARG if key, data, or out is NULL.
 *   A key or data pointer with len == 0 is allowed.
 * Returns BOWIE_ERR_CRYPTO if the underlying library reports a
 *   failure.
 */
bowie_error_t bowie_hash_hmac_sha256(const void *key, size_t key_len,
                                      const void *data, size_t data_len,
                                      bowie_hash_sha256_t *out);

#ifdef __cplusplus
}
#endif

#endif /* BOWIE_CRYPTO_HASH_H */
