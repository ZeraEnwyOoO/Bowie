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
 * The implementation uses the EVP interface, not the low-level
 * per-algorithm functions. On OpenSSL 3.0 the low-level
 * functions (MD5, SHA1, SHA256) are deprecated; the EVP
 * interface is the supported one. The EVP interface also
 * covers HMAC, so all four functions in this file use the
 * same API shape.
 *
 * EVP_MD_CTX is allocated and freed for every call. The
 * allocation is small and the hash functions are not on a hot
 * path; the clarity of the one-shot shape is worth the cost.
 * A future version that needs to hash many small buffers in a
 * loop can cache the context, but that is not a requirement
 * today.
 *
 * A data or key pointer with a length of zero is allowed. The
 * EVP functions accept it. The wrapper does not reject it; a
 * caller that hashes an empty buffer gets the hash of the
 * empty buffer, which is well-defined.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <openssl/evp.h>          EVP_MD_CTX, EVP_DigestInit_ex,
 *                            EVP_DigestUpdate, EVP_DigestFinal_ex,
 *                            EVP_MD_CTX_new, EVP_MD_CTX_free,
 *                            EVP_sha256, EVP_sha1, EVP_md5,
 *                            EVP_MAC, EVP_MAC_CTX,
 *                            EVP_MAC_fetch, EVP_MAC_init,
 *                            EVP_MAC_update, EVP_MAC_final,
 *                            EVP_MAC_CTX_free
 *   <openssl/core_names.h>   OSSL_MAC_PARAM_DIGEST
 *   "bowie/err.h"            error codes
 *   "crypto/hash.h"          the declarations
 * ============================================================================
 */

#include <openssl/evp.h>
#include <openssl/core_names.h>

#include <string.h>

#include "bowie/err.h"
#include "crypto/hash.h"

/*
 * ============================================================================
 * INTERNAL — DIGEST HELPER
 * ============================================================================
 *
 * Compute a digest with EVP. The caller supplies the digest
 * algorithm and the output length. The output buffer must be
 * at least out_len bytes.
 */

static bowie_error_t digest_evp(const EVP_MD *md,
                                 const void *data, size_t len,
                                 unsigned char *out,
                                 unsigned int out_len)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        return BOWIE_ERR_CRYPTO;
    }

    if (EVP_DigestInit_ex(ctx, md, NULL) != 1) {
        EVP_MD_CTX_free(ctx);
        return BOWIE_ERR_CRYPTO;
    }

    if (EVP_DigestUpdate(ctx, data, len) != 1) {
        EVP_MD_CTX_free(ctx);
        return BOWIE_ERR_CRYPTO;
    }

    unsigned int got = 0u;
    if (EVP_DigestFinal_ex(ctx, out, &got) != 1) {
        EVP_MD_CTX_free(ctx);
        return BOWIE_ERR_CRYPTO;
    }

    EVP_MD_CTX_free(ctx);

    if (got != out_len) {
        return BOWIE_ERR_CRYPTO;
    }

    return BOWIE_OK;
}

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

    return digest_evp(EVP_sha256(), data, len,
                      out->bytes, BOWIE_HASH_SHA256_LEN);
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

    return digest_evp(EVP_sha1(), data, len,
                      out->bytes, BOWIE_HASH_SHA1_LEN);
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

    return digest_evp(EVP_md5(), data, len,
                      out->bytes, BOWIE_HASH_MD5_LEN);
}

/*
 * ============================================================================
 * HMAC-SHA256
 * ============================================================================
 *
 * The EVP_MAC interface is the OpenSSL 3.0 replacement for the
 * HMAC() function. It is used here with the "HMAC" algorithm
 * and the SHA-256 digest.
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

    EVP_MAC *mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    if (mac == NULL) {
        return BOWIE_ERR_CRYPTO;
    }

    EVP_MAC_CTX *ctx = EVP_MAC_CTX_new(mac);
    if (ctx == NULL) {
        EVP_MAC_free(mac);
        return BOWIE_ERR_CRYPTO;
    }

    OSSL_PARAM params[2];
    params[0] = OSSL_PARAM_construct_utf8_string(
        OSSL_MAC_PARAM_DIGEST, "SHA256", 0);
    params[1] = OSSL_PARAM_construct_end();

    if (EVP_MAC_init(ctx, key, key_len, params) != 1) {
        EVP_MAC_CTX_free(ctx);
        EVP_MAC_free(mac);
        return BOWIE_ERR_CRYPTO;
    }

    if (EVP_MAC_update(ctx, data, data_len) != 1) {
        EVP_MAC_CTX_free(ctx);
        EVP_MAC_free(mac);
        return BOWIE_ERR_CRYPTO;
    }

    unsigned char digest[EVP_MAX_MD_SIZE];
    size_t out_len = 0u;

    if (EVP_MAC_final(ctx, digest, &out_len, sizeof(digest)) != 1) {
        EVP_MAC_CTX_free(ctx);
        EVP_MAC_free(mac);
        return BOWIE_ERR_CRYPTO;
    }

    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);

    if (out_len != BOWIE_HASH_SHA256_LEN) {
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
