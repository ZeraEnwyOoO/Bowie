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
 * BOWIE — KEYPAIR IMPLEMENTATION
 * ============================================================================
 *
 * X25519 key agreement backed by OpenSSL.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No signing. Ed25519 signatures are in sign.c.
 *   - No encryption. Symmetric encryption is in cipher.c.
 *   - No certificate parsing.
 *   - No key storage.
 *   - No streaming API.
 *   - No allocation in the success path beyond the EVP objects
 *     that OpenSSL requires.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * The implementation uses the EVP interface with
 * EVP_PKEY_X25519. The generation function uses
 * EVP_PKEY_keygen; the derivation and shared-secret functions
 * use EVP_PKEY_derive.
 *
 * The private key is generated from the platform entropy
 * source through OpenSSL's own DRBG. OpenSSL seeds its DRBG
 * from the platform source on first use. A caller that wants
 * to control the source must seed OpenSSL itself; this module
 * does not.
 *
 * The shared secret is 32 bytes. It is not a symmetric key.
 * A caller that needs a symmetric key must pass the secret
 * through a KDF. The recommended KDF is HKDF-SHA256. A caller
 * that does not have HKDF can use HMAC-SHA256 (in hash.h) as a
 * simple extract-then-expand.
 *
 * X25519 does not check that the remote public key is on the
 * curve. A low-order public key yields the all-zero shared
 * secret. The OpenSSL implementation returns a failure in
 * that case, and the wrapper maps it to BOWIE_ERR_CRYPTO. A
 * caller that needs to distinguish a low-order key from a
 * genuine library failure must check the remote public key
 * itself before the call.
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
 *   "bowie/err.h"                error codes
 *   "crypto/keypair.h"           the declarations
 * ============================================================================
 */

#include <openssl/evp.h>

#include <string.h>

#include "bowie/err.h"
#include "crypto/keypair.h"

/*
 * ============================================================================
 * GENERATE
 * ============================================================================
 */

bowie_error_t bowie_keypair_x25519_generate(
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
 * PUBLIC FROM PRIVATE
 * ============================================================================
 */

bowie_error_t bowie_keypair_x25519_public_from_private(
    const bowie_keypair_private_t *private_key,
    bowie_keypair_public_t *out)
{
    if (private_key == NULL || out == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }

    EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(
        EVP_PKEY_X25519, NULL,
        private_key->bytes, BOWIE_KEYPAIR_PRIVATE_LEN);
    if (pkey == NULL) {
        return BOWIE_ERR_CRYPTO;
    }

    size_t pub_len = BOWIE_KEYPAIR_PUBLIC_LEN;
    if (EVP_PKEY_get_raw_public_key(pkey, out->bytes,
                                     &pub_len) != 1) {
        EVP_PKEY_free(pkey);
        return BOWIE_ERR_CRYPTO;
    }

    EVP_PKEY_free(pkey);

    if (pub_len != BOWIE_KEYPAIR_PUBLIC_LEN) {
        return BOWIE_ERR_CRYPTO;
    }

    return BOWIE_OK;
}

/*
 * ============================================================================
 * SHARED SECRET
 * ============================================================================
 */

bowie_error_t bowie_keypair_x25519_shared(
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
 * END OF FILE
 * ============================================================================
 */
