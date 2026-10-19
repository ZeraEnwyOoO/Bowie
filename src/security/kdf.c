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
 * BOWIE — SECURITY: KDF (IMPLEMENTATION)
 * ============================================================================
 *
 * Implementation of the HKDF-SHA256 function declared in
 * security/kdf.h.
 *
 * The implementation calls OpenSSL directly. It does not use
 * crypto/hash.h; the security layer owns its own KDF for the
 * same reason session.c owns its own: the KDF is a policy
 * decision, not a general-purpose primitive.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No password hashing.
 *   - No key storage.
 *   - No allocation.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * HKDF is two steps: extract and expand. OpenSSL exposes
 * both through the EVP_PKEY_HKDF interface, which performs
 * the two steps in one call. The function here uses that
 * interface: EVP_PKEY_derive() runs extract and expand and
 * writes the output bytes.
 *
 * The salt is optional. A zero-length salt is allowed and
 * is treated by OpenSSL the same way RFC 5869 treats it: as
 * a string of HashLen zero bytes. The function passes the
 * salt pointer and length to OpenSSL as-is; it does not
 * substitute a zero-filled buffer for a NULL salt. OpenSSL
 * handles the NULL/zero case correctly.
 *
 * The info string is a domain separation tag. The function
 * passes it to OpenSSL unchanged. The caller is responsible
 * for the info string's meaning; two calls with the same
 * secret but different info strings produce independent
 * keys.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <openssl/evp.h>         EVP_PKEY_CTX, EVP_PKEY_HKDF,
 *                           EVP_PKEY_CTX_new_id,
 *                           EVP_PKEY_derive_init,
 *                           EVP_PKEY_derive,
 *                           EVP_PKEY_CTX_free,
 *                           EVP_PKEY_CTX_set_hkdf_md,
 *                           EVP_PKEY_CTX_set1_hkdf_salt,
 *                           EVP_PKEY_CTX_set1_hkdf_key,
 *                           EVP_PKEY_CTX_add1_hkdf_info,
 *                           EVP_sha256
 *   "bowie/err.h"           bowie_error_t
 *   "security/kdf.h"        declarations
 * ============================================================================
 */

#include <openssl/evp.h>
#include <openssl/kdf.h>

#include "bowie/err.h"
#include "security/kdf.h"

/*
 * ============================================================================
 * HKDF-SHA256
 * ============================================================================
 */

bowie_error_t bowie_security_kdf_hkdf_sha256(
    const uint8_t *ikm, size_t ikm_len,
    const uint8_t *salt, size_t salt_len,
    const uint8_t *info, size_t info_len,
    uint8_t *out, size_t out_len)
{
    EVP_PKEY_CTX *ctx;
    size_t        produced;
    int           rc;

    /*
     * Argument checks. A NULL pointer with a non-zero length
     * is an error; a NULL pointer with a zero length is
     * allowed for salt and info, and is required to be
     * rejected for ikm and out.
     */
    if (ikm == NULL && ikm_len > 0u) {
        return BOWIE_ERR_NULL_ARG;
    }
    if (salt == NULL && salt_len > 0u) {
        return BOWIE_ERR_NULL_ARG;
    }
    if (info == NULL && info_len > 0u) {
        return BOWIE_ERR_NULL_ARG;
    }
    if (out == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }
    if (out_len == 0u || out_len > BOWIE_KDF_MAX_OUT) {
        return BOWIE_ERR_INVAL;
    }

    /*
     * OpenSSL wants an int for the lengths. The header's
     * limit is small enough that the cast is safe; the
     * check below is a defensive guard for a future caller
     * that passes a larger buffer.
     */
    if (ikm_len > (size_t)INT_MAX ||
        salt_len > (size_t)INT_MAX ||
        info_len > (size_t)INT_MAX) {
        return BOWIE_ERR_TOO_LARGE;
    }

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (ctx == NULL) {
        return BOWIE_ERR_CRYPTO;
    }

    if (EVP_PKEY_derive_init(ctx) != 1) {
        EVP_PKEY_CTX_free(ctx);
        return BOWIE_ERR_CRYPTO;
    }

    if (EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256()) != 1) {
        EVP_PKEY_CTX_free(ctx);
        return BOWIE_ERR_CRYPTO;
    }

    /*
     * A NULL salt with a zero length is passed to OpenSSL
     * as-is. OpenSSL treats it as a zero-length salt, which
     * RFC 5869 defines as a string of HashLen zero bytes.
     */
    if (EVP_PKEY_CTX_set1_hkdf_salt(ctx, salt, (int)salt_len) != 1) {
        EVP_PKEY_CTX_free(ctx);
        return BOWIE_ERR_CRYPTO;
    }

    if (EVP_PKEY_CTX_set1_hkdf_key(ctx, ikm, (int)ikm_len) != 1) {
        EVP_PKEY_CTX_free(ctx);
        return BOWIE_ERR_CRYPTO;
    }

    if (EVP_PKEY_CTX_add1_hkdf_info(ctx, info,
                                    (int)info_len) != 1) {
        EVP_PKEY_CTX_free(ctx);
        return BOWIE_ERR_CRYPTO;
    }

    produced = out_len;
    rc = EVP_PKEY_derive(ctx, out, &produced);

    EVP_PKEY_CTX_free(ctx);

    if (rc != 1 || produced != out_len) {
        return BOWIE_ERR_CRYPTO;
    }

    return BOWIE_OK;
}

/*
 * ============================================================================
 * END OF FILE
 * ============================================================================
 */
