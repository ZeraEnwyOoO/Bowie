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
 * BOWIE — SECURITY: KEYPAIR (IMPLEMENTATION)
 * ============================================================================
 *
 * Implementation of the X25519 key agreement functions declared
 * in security/keypair.h.
 *
 * The implementation calls OpenSSL directly. It does not use
 * crypto/keypair.h.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No signing.
 *   - No encryption.
 *   - No I/O.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * X25519 keys are 32 bytes. The shared secret is 32 bytes. The
 * secret is a point on the curve, not a symmetric key; the
 * caller must pass it through a KDF.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <openssl/evp.h>              EVP_PKEY, EVP_PKEY_CTX,
 *                                EVP_PKEY_CTX_new_id,
 *                                EVP_PKEY_keygen_init,
 *                                EVP_PKEY_keygen,
 *                                EVP_PKEY_derive_init,
 *                                EVP_PKEY_derive_set_peer,
 *                                EVP_PKEY_derive,
 *                                EVP_PKEY_get_raw_public_key,
 *                                EVP_PKEY_get_raw_private_key,
 *                                EVP_PKEY_new_raw_private_key,
 *                                EVP_PKEY_new_raw_public_key,
 *                                EVP_PKEY_free,
 *                                EVP_PKEY_CTX_free,
 *                                EVP_PKEY_X25519
 *   "bowie/types.h"              types
 *   "bowie/err.h"                errors
 *   "security/keypair.h"         declarations
 * ============================================================================
 */

#include <openssl/evp.h>

#include "bowie/types.h"
#include "bowie/err.h"
#include "security/keypair.h"

/*
 * ============================================================================
 * GENERATE
 * ============================================================================
 */

bowie_error_t bowie_security_keypair_generate(
    bowie_keypair_public_t *out_public,
    bowie_keypair_private_t *out_private)
{
    if (out_public == NULL || out_private == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    if (ctx == NULL) {
        return BOWIE_ERR_CRYPTO;
    }

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

    size_t pub_len = BOWIE_KEYPAIR_PUBLIC_LEN;
    size_t priv_len = BOWIE_KEYPAIR_PRIVATE_LEN;

    if (EVP_PKEY_get_raw_public_key(pkey, out_public->bytes,
                                     &pub_len) != 1) {
        EVP_PKEY_free(pkey);
        return BOWIE_ERR_CRYPTO;
    }
    if (EVP_PKEY_get_raw_private_key(pkey, out_private->bytes,
                                      &priv_len) != 1) {
        EVP_PKEY_free(pkey);
        return BOWIE_ERR_CRYPTO;
    }

    EVP_PKEY_free(pkey);

    if (pub_len != BOWIE_KEYPAIR_PUBLIC_LEN ||
        priv_len != BOWIE_KEYPAIR_PRIVATE_LEN) {
        return BOWIE_ERR_CRYPTO;
    }

    return BOWIE_OK;
}

/*
 * ============================================================================
 * SHARED SECRET
 * ============================================================================
 */

bowie_error_t bowie_security_keypair_shared(
    const bowie_keypair_private_t *local_private,
    const bowie_keypair_public_t *remote_public,
    bowie_keypair_shared_t *out)
{
    if (local_private == NULL || remote_public == NULL ||
        out == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }

    EVP_PKEY *local = EVP_PKEY_new_raw_private_key(
        EVP_PKEY_X25519, NULL,
        local_private->bytes, BOWIE_KEYPAIR_PRIVATE_LEN);
    if (local == NULL) {
        return BOWIE_ERR_CRYPTO;
    }

    EVP_PKEY *remote = EVP_PKEY_new_raw_public_key(
        EVP_PKEY_X25519, NULL,
        remote_public->bytes, BOWIE_KEYPAIR_PUBLIC_LEN);
    if (remote == NULL) {
        EVP_PKEY_free(local);
        return BOWIE_ERR_CRYPTO;
    }

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(local, NULL);
    if (ctx == NULL) {
        EVP_PKEY_free(remote);
        EVP_PKEY_free(local);
        return BOWIE_ERR_CRYPTO;
    }

    if (EVP_PKEY_derive_init(ctx) != 1) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(remote);
        EVP_PKEY_free(local);
        return BOWIE_ERR_CRYPTO;
    }

    if (EVP_PKEY_derive_set_peer(ctx, remote) != 1) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(remote);
        EVP_PKEY_free(local);
        return BOWIE_ERR_CRYPTO;
    }

    size_t shared_len = BOWIE_KEYPAIR_SHARED_LEN;
    if (EVP_PKEY_derive(ctx, out->bytes, &shared_len) != 1) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(remote);
        EVP_PKEY_free(local);
        return BOWIE_ERR_CRYPTO;
    }

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(remote);
    EVP_PKEY_free(local);

    if (shared_len != BOWIE_KEYPAIR_SHARED_LEN) {
        return BOWIE_ERR_CRYPTO;
    }

    return BOWIE_OK;
}

/*
 * ============================================================================
 * END OF SECURITY KEYPAIR IMPLEMENTATION
 * ============================================================================
 */
