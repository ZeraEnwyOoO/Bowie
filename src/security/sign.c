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
 * BOWIE — SECURITY: SIGN (IMPLEMENTATION)
 * ============================================================================
 *
 * Implementation of the Ed25519 signing functions declared in
 * security/sign.h.
 *
 * The implementation calls OpenSSL directly. It does not use
 * crypto/sign.h.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No key generation.
 *   - No encryption.
 *   - No I/O.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * The private key is 64 bytes (seed || public). Only the first
 * 32 bytes (the seed) are used for signing; OpenSSL derives
 * the public key from the seed.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <openssl/evp.h>              EVP_PKEY, EVP_MD_CTX,
 *                                EVP_PKEY_new_raw_private_key,
 *                                EVP_PKEY_new_raw_public_key,
 *                                EVP_PKEY_free,
 *                                EVP_MD_CTX_new, EVP_MD_CTX_free,
 *                                EVP_DigestSignInit,
 *                                EVP_DigestSign,
 *                                EVP_DigestVerifyInit,
 *                                EVP_DigestVerify,
 *                                EVP_PKEY_ED25519
 *   "bowie/types.h"              types
 *   "bowie/err.h"                errors
 *   "security/sign.h"            declarations
 * ============================================================================
 */

#include <openssl/evp.h>
#include <string.h>

#include "bowie/types.h"
#include "bowie/err.h"
#include "security/sign.h"

/*
 * ============================================================================
 * SIGN
 * ============================================================================
 */

bowie_error_t bowie_security_sign(
    const bowie_sign_private_t *private_key,
    const void *msg, size_t msg_len,
    bowie_sign_signature_t *out)
{
    if (private_key == NULL || out == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }
    if (msg == NULL && msg_len > 0u) {
        return BOWIE_ERR_NULL_ARG;
    }

    EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(
        EVP_PKEY_ED25519, NULL,
        private_key->bytes, BOWIE_SIGN_PUBLIC_LEN);
    if (pkey == NULL) {
        return BOWIE_ERR_CRYPTO;
    }

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        EVP_PKEY_free(pkey);
        return BOWIE_ERR_CRYPTO;
    }

    if (EVP_DigestSignInit(ctx, NULL, NULL, NULL, pkey) != 1) {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return BOWIE_ERR_CRYPTO;
    }

    size_t sig_len = BOWIE_SIGN_SIGNATURE_LEN;

    if (EVP_DigestSign(ctx, out->bytes, &sig_len,
                       (const unsigned char *)msg, msg_len) != 1) {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return BOWIE_ERR_CRYPTO;
    }

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);

    if (sig_len != BOWIE_SIGN_SIGNATURE_LEN) {
        return BOWIE_ERR_CRYPTO;
    }

    return BOWIE_OK;
}

/*
 * ============================================================================
 * VERIFY
 * ============================================================================
 */

bowie_error_t bowie_security_verify(
    const bowie_sign_public_t *public_key,
    const void *msg, size_t msg_len,
    const bowie_sign_signature_t *signature)
{
    if (public_key == NULL || signature == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }
    if (msg == NULL && msg_len > 0u) {
        return BOWIE_ERR_NULL_ARG;
    }

    EVP_PKEY *pkey = EVP_PKEY_new_raw_public_key(
        EVP_PKEY_ED25519, NULL,
        public_key->bytes, BOWIE_SIGN_PUBLIC_LEN);
    if (pkey == NULL) {
        return BOWIE_ERR_CRYPTO;
    }

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        EVP_PKEY_free(pkey);
        return BOWIE_ERR_CRYPTO;
    }

    if (EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, pkey) != 1) {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return BOWIE_ERR_CRYPTO;
    }

    int rc = EVP_DigestVerify(ctx, signature->bytes,
                               BOWIE_SIGN_SIGNATURE_LEN,
                               (const unsigned char *)msg, msg_len);

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);

    if (rc == 1) {
        return BOWIE_OK;
    }
    if (rc == 0) {
        return BOWIE_ERR_SIGN_INVALID;
    }
    return BOWIE_ERR_CRYPTO;
}

/*
 *=============================================================================
 *bowie security sign generate
 *=============================================================================
 */
bowie_error_t bowie_security_sign_generate(
    bowie_sign_public_t *out_public,
    bowie_sign_private_t *out_private)
{
    if (out_public == NULL || out_private == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
    if (ctx == NULL) return BOWIE_ERR_CRYPTO;

    if (EVP_PKEY_keygen_init(ctx) != 1) {
        EVP_PKEY_CTX_free(ctx);
        return BOWIE_ERR_CRYPTO;
    }

    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_keygen(ctx, &pkey) != 1) {
        EVP_PKEY_CTX_free(ctx);
        return BOWIE_ERR_CRYPTO;
    }

    EVP_PKEY_CTX_free(ctx);

    size_t pub_len = BOWIE_SIGN_PUBLIC_LEN;
    size_t priv_len = BOWIE_SIGN_PRIVATE_LEN;

    if (EVP_PKEY_get_raw_public_key(pkey, out_public->bytes, &pub_len) != 1) {
        EVP_PKEY_free(pkey);
        return BOWIE_ERR_CRYPTO;
    }
    if (EVP_PKEY_get_raw_private_key(pkey, out_private->bytes, &priv_len) != 1) {
        EVP_PKEY_free(pkey);
        return BOWIE_ERR_CRYPTO;
    }

    EVP_PKEY_free(pkey);
    return BOWIE_OK;
}

bowie_error_t bowie_security_sign_from_seed(
    const uint8_t seed[BOWIE_SIGN_SEED_LEN],
    bowie_sign_public_t *out_public,
    bowie_sign_private_t *out_private)
{
    if (seed == NULL || out_public == NULL || out_private == NULL)
        return BOWIE_ERR_NULL_ARG;
    EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL,
                                                  seed, BOWIE_SIGN_SEED_LEN);
    if (pkey == NULL) return BOWIE_ERR_CRYPTO;
    size_t len = BOWIE_SIGN_PUBLIC_LEN;
    int ok = EVP_PKEY_get_raw_public_key(pkey, out_public->bytes, &len);
    EVP_PKEY_free(pkey);
    if (ok != 1 || len != BOWIE_SIGN_PUBLIC_LEN) return BOWIE_ERR_CRYPTO;
    memcpy(out_private->bytes, seed, BOWIE_SIGN_SEED_LEN);
    memcpy(out_private->bytes + BOWIE_SIGN_SEED_LEN, out_public->bytes,
           BOWIE_SIGN_PUBLIC_LEN);
    return BOWIE_OK;
}

/*
 * ============================================================================
 * END OF SECURITY SIGN IMPLEMENTATION
 * ============================================================================
 */
