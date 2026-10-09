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
 * BOWIE — HASH IMPLEMENTATION
 * ============================================================================
 *
 * Cryptographic hash functions backed by OpenSSL.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No password hashing. Bowie does not store passwords.
 *   - No key derivation. HMAC is provided; a full KDF is not.
 *   - No streaming API. Every function hashes a complete
 *     buffer.
 *   - No allocation. Every function writes to a caller-supplied
 *     output buffer.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * The implementation is a thin wrapper over OpenSSL. The
 * OpenSSL one-shot functions (SHA256, SHA1, MD5, HMAC) are
 * used directly. They take a complete buffer and produce a
 * complete digest; there is no context to manage.
 *
 * OpenSSL's return values are checked. The one-shot functions
 * return NULL on failure; the wrapper converts that to
 * BOWIE_ERR_CRYPTO. In practice a NULL return means the output
 * pointer was NULL, which the wrapper already rejects, so the
 * conversion is a defensive measure.
 *
 * A data or key pointer with a length of zero is allowed. The
 * OpenSSL functions accept it. The wrapper does not reject it;
 * a caller that hashes an empty buffer gets the hash of the
 * empty buffer, which is well-defined.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <openssl/sha.h>          SHA1, SHA256
 *   <openssl/md5.h>          MD5
 *   <openssl/hmac.h>         HMAC
 *   <openssl/evp.h>          EVP_MAX_MD_SIZE
 *   "bowie/err.h"            error codes
 *   "bowie/crypto/hash.h"    the declarations
 * ============================================================================
 */

#include <openssl/sha.h>
#include <openssl/md5.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>

#include <string.h>

#include "bowie/err.h"
#include "bowie/crypto/hash.h"

/*
 * ============================================================================
 * SHA-256
 * ============================================================================
 */

bowie_error_t bowie_hash_sha256(const void *data, size_t len,
                                 bowie_hash_sha256_t *out)
{
    if (out == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }
    if (data == NULL && len > 0u) {
        return BOWIE_ERR_NULL_ARG;
    }

    unsigned char digest[SHA256_DIGEST_LENGTH];

    if (SHA256((const unsigned char *)data, len, digest) == NULL) {
        return BOWIE_ERR_CRYPTO;
    }

    memcpy(out->bytes, digest, SHA256_DIGEST_LENGTH);
    return BOWIE_OK;
}

/*
 * ============================================================================
 * SHA-1
 * ============================================================================
 */

bowie_error_t bowie_hash_sha1(const void *data, size_t len,
                               bowie_hash_sha1_t *out)
{
    if (out == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }
    if (data == NULL && len > 0u) {
        return BOWIE_ERR_NULL_ARG;
    }

    unsigned char digest[SHA_DIGEST_LENGTH];

    if (SHA1((const unsigned char *)data, len, digest) == NULL) {
        return BOWIE_ERR_CRYPTO;
    }

    memcpy(out->bytes, digest, SHA_DIGEST_LENGTH);
    return BOWIE_OK;
}

/*
 * ============================================================================
 * MD5
 * ============================================================================
 */

bowie_error_t bowie_hash_md5(const void *data, size_t len,
                              bowie_hash_md5_t *out)
{
    if (out == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }
    if (data == NULL && len > 0u) {
        return BOWIE_ERR_NULL_ARG;
    }

    unsigned char digest[MD5_DIGEST_LENGTH];

    if (MD5((const unsigned char *)data, len, digest) == NULL) {
        return BOWIE_ERR_CRYPTO;
    }

    memcpy(out->bytes, digest, MD5_DIGEST_LENGTH);
    return BOWIE_OK;
}

/*
 * ============================================================================
 * HMAC-SHA256
 * ============================================================================
 */

bowie_error_t bowie_hash_hmac_sha256(const void *key, size_t key_len,
                                      const void *data, size_t data_len,
                                      bowie_hash_sha256_t *out)
{
    if (out == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }
    if (key == NULL && key_len > 0u) {
        return BOWIE_ERR_NULL_ARG;
    }
    if (data == NULL && data_len > 0u) {
        return BOWIE_ERR_NULL_ARG;
    }

    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int  digest_len = 0u;

    if (HMAC(EVP_sha256(),
             key, (int)key_len,
             (const unsigned char *)data, data_len,
             digest, &digest_len) == NULL) {
        return BOWIE_ERR_CRYPTO;
    }

    if (digest_len != BOWIE_HASH_SHA256_LEN) {
        return BOWIE_ERR_CRYPTO;
    }

    memcpy(out->bytes, digest, BOWIE_HASH_SHA256_LEN);
    return BOWIE_OK;
}

/*
 * ============================================================================
 * END OF FILE
 * ============================================================================
 */
