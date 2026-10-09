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
 * BOWIE — CIPHER IMPLEMENTATION
 * ============================================================================
 *
 * Symmetric encryption and decryption backed by OpenSSL.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No asymmetric encryption. Public-key cryptography is in
 *     sign.c and keypair.c.
 *   - No key exchange. X25519 is in keypair.c.
 *   - No password-based encryption.
 *   - No streaming API. Every function encrypts or decrypts a
 *     complete buffer.
 *   - No allocation. Every function writes to a caller-supplied
 *     output buffer.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * The implementation uses the EVP interface. For GCM, the
 * sequence is:
 *
 *   EVP_EncryptInit_ex  (with cipher and key)
 *   EVP_CIPHER_CTX_ctrl (set IV length to 12)
 *   EVP_EncryptInit_ex  (with nonce and no key, sets IV)
 *   EVP_EncryptUpdate   (AAD, if any)
 *   EVP_EncryptUpdate   (plaintext)
 *   EVP_EncryptFinal_ex (final block)
 *   EVP_CIPHER_CTX_ctrl (get tag)
 *
 * The EVP_EncryptFinal_ex call may produce additional output
 * bytes for block ciphers. For GCM, it produces none; for CTR,
 * it also produces none. The wrapper accounts for the
 * additional bytes in the output length.
 *
 * The decryption sequence for GCM is the mirror image, with
 * one important difference: the tag is set before the final
 * call, and EVP_DecryptFinal_ex returns 0 if the tag does not
 * verify. The wrapper maps that 0 to BOWIE_ERR_CRYPTO and
 * leaves the output buffer alone.
 *
 * The output buffer size check is done before any EVP call. A
 * caller that passes a buffer that is too small gets
 * BOWIE_ERR_TOO_SMALL with no side effects.
 *
 * A NULL pointer with a length of zero is allowed for AAD and
 * for plaintext. The EVP functions accept it.
 *
 * ----------------------------------------------------------------------------
 * Length handling
 * ----------------------------------------------------------------------------
 *
 * OpenSSL's EVP interface takes the input and output length as
 * an int. Bowie's API takes the length as a size_t. The
 * conversion from size_t to int is not safe unless the value
 * fits in an int.
 *
 * Every function in this file checks that every length it is
 * about to pass to OpenSSL fits in an int before the call. A
 * length that does not fit is rejected with
 * BOWIE_ERR_TOO_LARGE. This is a deliberate limit: a single
 * cipher operation of more than 2 GiB is not a use case Bowie
 * has, and the check prevents a silent truncation that would
 * produce a wrong result.
 *
 * The output length in the GCM encrypt function is
 * plaintext_len + BOWIE_CIPHER_TAG_LEN. The addition is
 * checked for size_t overflow before the sum is used. A
 * plaintext_len close to SIZE_MAX would otherwise wrap, and
 * the buffer size check would pass for a buffer that is
 * actually too small.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <openssl/evp.h>              EVP_CIPHER_CTX, EVP_aes_256_gcm,
 *                                EVP_aes_256_ctr, EVP_EncryptInit_ex,
 *                                EVP_DecryptInit_ex, EVP_EncryptUpdate,
 *                                EVP_DecryptUpdate, EVP_EncryptFinal_ex,
 *                                EVP_DecryptFinal_ex, EVP_CIPHER_CTX_ctrl,
 *                                EVP_CIPHER_CTX_new, EVP_CIPHER_CTX_free
 *   <limits.h>                   INT_MAX
 *   <string.h>                   memcpy
 *   "bowie/err.h"                error codes
 *   "crypto/cipher.h"            the declarations
 * ============================================================================
 */

#include <openssl/evp.h>

#include <limits.h>
#include <string.h>

#include "bowie/err.h"
#include "crypto/cipher.h"

/*
 * ============================================================================
 * INTERNAL — LENGTH CHECK
 * ============================================================================
 *
 * OpenSSL's EVP interface takes input and output lengths as
 * int. A size_t that does not fit in an int is rejected before
 * the call.
 *
 * The check is a single comparison. It is written as a macro
 * so that the intent is clear at the call site.
 */

#define BOWIE_CIPHER_FITS_INT(n) ((n) <= (size_t)INT_MAX)

/*
 * ============================================================================
 * AES-256-GCM — ENCRYPT
 * ============================================================================
 */

bowie_error_t bowie_cipher_aes256_gcm_encrypt(
    const uint8_t key[BOWIE_CIPHER_KEY_LEN],
    const uint8_t nonce[BOWIE_CIPHER_GCM_NONCE_LEN],
    const void *aad, size_t aad_len,
    const void *plaintext, size_t plaintext_len,
    uint8_t *out, size_t out_cap,
    size_t *out_len)
{
    if (key == NULL || nonce == NULL || out == NULL ||
        out_len == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }
    if (plaintext == NULL && plaintext_len > 0u) {
        return BOWIE_ERR_NULL_ARG;
    }
    if (aad == NULL && aad_len > 0u) {
        return BOWIE_ERR_NULL_ARG;
    }

    /*
     * OpenSSL takes the length as an int. Reject any length
     * that does not fit before the multiplication and the
     * buffer size check.
     */
    if (!BOWIE_CIPHER_FITS_INT(plaintext_len) ||
        !BOWIE_CIPHER_FITS_INT(aad_len)) {
        return BOWIE_ERR_TOO_LARGE;
    }

    /*
     * The output is the ciphertext followed by the tag. The
     * required size is plaintext_len + 16. The addition is
     * checked for size_t overflow before the sum is used.
     */
    if (plaintext_len > SIZE_MAX - BOWIE_CIPHER_TAG_LEN) {
        return BOWIE_ERR_TOO_LARGE;
    }
    size_t required = plaintext_len + BOWIE_CIPHER_TAG_LEN;
    if (out_cap < required) {
        return BOWIE_ERR_TOO_SMALL;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        return BOWIE_ERR_CRYPTO;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(),
                            NULL, NULL, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return BOWIE_ERR_CRYPTO;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                             BOWIE_CIPHER_GCM_NONCE_LEN,
                             NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return BOWIE_ERR_CRYPTO;
    }

    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return BOWIE_ERR_CRYPTO;
    }

    int len = 0;

    if (aad_len > 0u) {
        if (EVP_EncryptUpdate(ctx, NULL, &len,
                               (const unsigned char *)aad,
                               (int)aad_len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return BOWIE_ERR_CRYPTO;
        }
    }

    if (plaintext_len > 0u) {
        if (EVP_EncryptUpdate(ctx, out, &len,
                               (const unsigned char *)plaintext,
                               (int)plaintext_len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return BOWIE_ERR_CRYPTO;
        }
    } else {
        len = 0;
    }

    size_t written = (size_t)len;

    int final_len = 0;
    if (EVP_EncryptFinal_ex(ctx, out + written, &final_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return BOWIE_ERR_CRYPTO;
    }
    written += (size_t)final_len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG,
                             BOWIE_CIPHER_TAG_LEN,
                             out + written) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return BOWIE_ERR_CRYPTO;
    }
    written += BOWIE_CIPHER_TAG_LEN;

    EVP_CIPHER_CTX_free(ctx);

    *out_len = written;
    return BOWIE_OK;
}

/*
 * ============================================================================
 * AES-256-GCM — DECRYPT
 * ============================================================================
 */

bowie_error_t bowie_cipher_aes256_gcm_decrypt(
    const uint8_t key[BOWIE_CIPHER_KEY_LEN],
    const uint8_t nonce[BOWIE_CIPHER_GCM_NONCE_LEN],
    const void *aad, size_t aad_len,
    const void *ciphertext, size_t ciphertext_len,
    uint8_t *out, size_t out_cap,
    size_t *out_len)
{
    if (key == NULL || nonce == NULL || out == NULL ||
        out_len == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }
    if (ciphertext == NULL && ciphertext_len > 0u) {
        return BOWIE_ERR_NULL_ARG;
    }
    if (aad == NULL && aad_len > 0u) {
        return BOWIE_ERR_NULL_ARG;
    }

    if (!BOWIE_CIPHER_FITS_INT(ciphertext_len) ||
        !BOWIE_CIPHER_FITS_INT(aad_len)) {
        return BOWIE_ERR_TOO_LARGE;
    }

    if (ciphertext_len < BOWIE_CIPHER_TAG_LEN) {
        return BOWIE_ERR_CRYPTO;
    }

    size_t ct_len = ciphertext_len - BOWIE_CIPHER_TAG_LEN;

    if (out_cap < ct_len) {
        return BOWIE_ERR_TOO_SMALL;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        return BOWIE_ERR_CRYPTO;
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(),
                            NULL, NULL, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return BOWIE_ERR_CRYPTO;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                             BOWIE_CIPHER_GCM_NONCE_LEN,
                             NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return BOWIE_ERR_CRYPTO;
    }

    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return BOWIE_ERR_CRYPTO;
    }

    int len = 0;

    if (aad_len > 0u) {
        if (EVP_DecryptUpdate(ctx, NULL, &len,
                               (const unsigned char *)aad,
                               (int)aad_len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return BOWIE_ERR_CRYPTO;
        }
    }

    if (ct_len > 0u) {
        if (EVP_DecryptUpdate(ctx, out, &len,
                               (const unsigned char *)ciphertext,
                               (int)ct_len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return BOWIE_ERR_CRYPTO;
        }
    } else {
        len = 0;
    }

    size_t written = (size_t)len;

    const unsigned char *tag =
        (const unsigned char *)ciphertext + ct_len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG,
                             BOWIE_CIPHER_TAG_LEN,
                             (void *)tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return BOWIE_ERR_CRYPTO;
    }

    int final_len = 0;
    if (EVP_DecryptFinal_ex(ctx, out + written, &final_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return BOWIE_ERR_CRYPTO;
    }
    written += (size_t)final_len;

    EVP_CIPHER_CTX_free(ctx);

    *out_len = written;
    return BOWIE_OK;
}

/*
 * ============================================================================
 * AES-256-CTR — ENCRYPT
 * ============================================================================
 */

bowie_error_t bowie_cipher_aes256_ctr_encrypt(
    const uint8_t key[BOWIE_CIPHER_KEY_LEN],
    const uint8_t nonce[BOWIE_CIPHER_CTR_NONCE_LEN],
    const void *plaintext, size_t plaintext_len,
    uint8_t *out, size_t out_cap,
    size_t *out_len)
{
    if (key == NULL || nonce == NULL || out == NULL ||
        out_len == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }
    if (plaintext == NULL && plaintext_len > 0u) {
        return BOWIE_ERR_NULL_ARG;
    }

    if (!BOWIE_CIPHER_FITS_INT(plaintext_len)) {
        return BOWIE_ERR_TOO_LARGE;
    }

    if (out_cap < plaintext_len) {
        return BOWIE_ERR_TOO_SMALL;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        return BOWIE_ERR_CRYPTO;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(),
                            NULL, key, nonce) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return BOWIE_ERR_CRYPTO;
    }

    int len = 0;
    size_t written = 0u;

    if (plaintext_len > 0u) {
        if (EVP_EncryptUpdate(ctx, out, &len,
                               (const unsigned char *)plaintext,
                               (int)plaintext_len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return BOWIE_ERR_CRYPTO;
        }
        written = (size_t)len;
    }

    int final_len = 0;
    if (EVP_EncryptFinal_ex(ctx, out + written, &final_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return BOWIE_ERR_CRYPTO;
    }
    written += (size_t)final_len;

    EVP_CIPHER_CTX_free(ctx);

    *out_len = written;
    return BOWIE_OK;
}

/*
 * ============================================================================
 * AES-256-CTR — DECRYPT
 * ============================================================================
 */

bowie_error_t bowie_cipher_aes256_ctr_decrypt(
    const uint8_t key[BOWIE_CIPHER_KEY_LEN],
    const uint8_t nonce[BOWIE_CIPHER_CTR_NONCE_LEN],
    const void *ciphertext, size_t ciphertext_len,
    uint8_t *out, size_t out_cap,
    size_t *out_len)
{
    if (key == NULL || nonce == NULL || out == NULL ||
        out_len == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }
    if (ciphertext == NULL && ciphertext_len > 0u) {
        return BOWIE_ERR_NULL_ARG;
    }

    if (!BOWIE_CIPHER_FITS_INT(ciphertext_len)) {
        return BOWIE_ERR_TOO_LARGE;
    }

    if (out_cap < ciphertext_len) {
        return BOWIE_ERR_TOO_SMALL;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        return BOWIE_ERR_CRYPTO;
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_ctr(),
                            NULL, key, nonce) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return BOWIE_ERR_CRYPTO;
    }

    int len = 0;
    size_t written = 0u;

    if (ciphertext_len > 0u) {
        if (EVP_DecryptUpdate(ctx, out, &len,
                               (const unsigned char *)ciphertext,
                               (int)ciphertext_len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return BOWIE_ERR_CRYPTO;
        }
        written = (size_t)len;
    }

    int final_len = 0;
    if (EVP_DecryptFinal_ex(ctx, out + written, &final_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return BOWIE_ERR_CRYPTO;
    }
    written += (size_t)final_len;

    EVP_CIPHER_CTX_free(ctx);

    *out_len = written;
    return BOWIE_OK;
}

/*
 * ============================================================================
 * END OF FILE
 * ============================================================================
 */
