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
 * BOWIE — SECURITY: SESSION (IMPLEMENTATION)
 * ============================================================================
 *
 * Implementation of the session helpers declared in
 * security/session.h.
 *
 * The implementation calls OpenSSL directly. It does not use
 * crypto/cipher.h or crypto/hash.h.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No key agreement. The X25519 exchange is done by the
 *     caller.
 *   - No identity or grant.
 *   - No I/O.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * The session key is derived with HKDF-SHA256 (RFC 5869). The
 * shared secret is the IKM, the salt is empty, and the info
 * string is "bowie session key". The output is 32 bytes.
 *
 * Every datagram begins with its 64-bit big-endian sequence
 * number, followed by ciphertext and a 16-byte GCM tag. The
 * sequence number is authenticated as associated data. It
 * selects the 12-byte nonce:
 *
 *     [ 4 bytes: zero ] [ 8 bytes: counter, big-endian ]
 *
 * The receiver tracks a 64-packet replay window, so packet
 * loss and reordering do not desynchronize the session and
 * duplicate or stale packets are rejected.
 *
 * The handle stores the key in a fixed-size buffer. The buffer
 * is wiped before the handle is freed with an explicit
 * OPENSSL_cleanse.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <openssl/evp.h>         EVP_CIPHER_CTX, EVP_aes_256_gcm,
 *                           EVP_EncryptInit_ex, EVP_DecryptInit_ex,
 *                           EVP_EncryptUpdate, EVP_DecryptUpdate,
 *                           EVP_EncryptFinal_ex, EVP_DecryptFinal_ex,
 *                           EVP_CIPHER_CTX_ctrl,
 *                           EVP_CIPHER_CTX_new, EVP_CIPHER_CTX_free,
 *                           EVP_PKEY_HKDF, EVP_PKEY_CTX_new_id,
 *                           EVP_PKEY_derive_init,
 *                           EVP_PKEY_derive, EVP_PKEY_CTX_free,
 *                           EVP_sha256
 *   <openssl/kdf.h>         EVP_PKEY_CTX_set_hkdf_md,
 *                           EVP_PKEY_CTX_set1_hkdf_salt,
 *                           EVP_PKEY_CTX_set1_hkdf_key,
 *                           EVP_PKEY_CTX_add1_hkdf_info
 *   <openssl/crypto.h>      OPENSSL_cleanse
 *   <limits.h>              INT_MAX
 *   <stdlib.h>              calloc, free
 *   <string.h>              memcpy, memset
 *   "bowie/types.h"         types
 *   "bowie/err.h"           errors
 *   "security/session.h"    declarations
 * ============================================================================
 */

#include <openssl/evp.h>
#include <openssl/kdf.h>    
#include <openssl/crypto.h>

#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include "bowie/types.h"
#include "bowie/err.h"
#include "security/session.h"

/*
 * ============================================================================
 * CONSTANTS
 * ============================================================================
 */
 
#define BOWIE_SESSION_NONCE_LEN     12

#define BOWIE_SESSION_INFO          "bowie session key"
#define BOWIE_SESSION_INFO_LEN      17u

/*
 * ============================================================================
 * HANDLE
 * ============================================================================
 */

struct bowie_session {
    uint8_t            tx_key[BOWIE_SESSION_KEY_LEN];
    uint8_t            rx_key[BOWIE_SESSION_KEY_LEN];
    uint64_t           tx_counter;
    uint64_t           rx_highest;
    uint64_t           rx_window;
    int                rx_initialized;
    bowie_session_id_t id;
};

/*
 * ============================================================================
 * INTERNAL — HKDF
 * ============================================================================
 */

static bowie_error_t derive_key(const uint8_t *secret,
                                size_t secret_len,
                                uint8_t *out_key)
{
    EVP_PKEY_CTX *ctx;
    size_t        out_len;
    int           rc;
    unsigned char salt[1] = { 0 };

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

    if (EVP_PKEY_CTX_set1_hkdf_salt(ctx, salt, 0) != 1) {
        EVP_PKEY_CTX_free(ctx);
        return BOWIE_ERR_CRYPTO;
    }

    if (EVP_PKEY_CTX_set1_hkdf_key(ctx, secret, (int)secret_len) != 1) {
        EVP_PKEY_CTX_free(ctx);
        return BOWIE_ERR_CRYPTO;
    }

    if (EVP_PKEY_CTX_add1_hkdf_info(ctx,
                                     (const unsigned char *)BOWIE_SESSION_INFO,
                                     (int)BOWIE_SESSION_INFO_LEN) != 1) {
        EVP_PKEY_CTX_free(ctx);
        return BOWIE_ERR_CRYPTO;
    }

    out_len = BOWIE_SESSION_KEY_LEN;

    rc = EVP_PKEY_derive(ctx, out_key, &out_len);

    EVP_PKEY_CTX_free(ctx);

    if (rc != 1 || out_len != BOWIE_SESSION_KEY_LEN) {
        return BOWIE_ERR_CRYPTO;
    }

    return BOWIE_OK;
}

/*
 * ============================================================================
 * INTERNAL — NONCE
 * ============================================================================
 */

static void make_nonce(uint64_t counter, uint8_t out[BOWIE_SESSION_NONCE_LEN])
{
    out[0]  = 0;
    out[1]  = 0;
    out[2]  = 0;
    out[3]  = 0;
    out[4]  = (uint8_t)(counter >> 56);
    out[5]  = (uint8_t)(counter >> 48);
    out[6]  = (uint8_t)(counter >> 40);
    out[7]  = (uint8_t)(counter >> 32);
    out[8]  = (uint8_t)(counter >> 24);
    out[9]  = (uint8_t)(counter >> 16);
    out[10] = (uint8_t)(counter >> 8);
    out[11] = (uint8_t)(counter);
}

static void encode_counter(uint64_t counter, uint8_t out[BOWIE_SESSION_COUNTER_LEN])
{
    for (size_t i = 0u; i < BOWIE_SESSION_COUNTER_LEN; i++)
        out[i] = (uint8_t)(counter >> (56u - (unsigned)(i * 8u)));
}

static uint64_t decode_counter(const uint8_t in[BOWIE_SESSION_COUNTER_LEN])
{
    uint64_t counter = 0u;
    for (size_t i = 0u; i < BOWIE_SESSION_COUNTER_LEN; i++)
        counter = (counter << 8) | in[i];
    return counter;
}

static int replay_candidate(const bowie_session_t *session, uint64_t counter)
{
    if (!session->rx_initialized || counter > session->rx_highest) return 1;
    uint64_t distance = session->rx_highest - counter;
    return distance < 64u && (session->rx_window & (UINT64_C(1) << distance)) == 0u;
}

static void replay_commit(bowie_session_t *session, uint64_t counter)
{
    if (!session->rx_initialized) {
        session->rx_highest = counter;
        session->rx_window = 1u;
        session->rx_initialized = 1;
    } else if (counter > session->rx_highest) {
        uint64_t shift = counter - session->rx_highest;
        session->rx_window = shift >= 64u ? 1u : (session->rx_window << shift) | 1u;
        session->rx_highest = counter;
    } else {
        session->rx_window |= UINT64_C(1) << (session->rx_highest - counter);
    }
}

/*
 * ============================================================================
 * LIFECYCLE
 * ============================================================================
 */

bowie_error_t bowie_session_new(const uint8_t *shared_secret,
                                size_t shared_secret_len,
                                const bowie_session_id_t *session_id,
                                bowie_session_t **out)
{
    bowie_session_t *s;
    bowie_error_t    rc;

    if (out == NULL || shared_secret == NULL ||
        session_id == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }

    *out = NULL;

    if (shared_secret_len == 0) {
        return BOWIE_ERR_INVAL;
    }

    if (bowie_session_id_is_zero(session_id)) {
        return BOWIE_ERR_INVAL;
    }

    s = (bowie_session_t *)calloc(1, sizeof(*s));

    if (s == NULL) {
        return BOWIE_ERR_NOMEM;
    }

    rc = derive_key(shared_secret, shared_secret_len, s->tx_key);

    if (rc != BOWIE_OK) {
        OPENSSL_cleanse(s, sizeof(*s));
        free(s);
        return rc;
    }

    memcpy(s->rx_key, s->tx_key, sizeof(s->rx_key));
    s->tx_counter = 0;
    memcpy(&s->id, session_id, sizeof(s->id));

    *out = s;

    return BOWIE_OK;
}

void bowie_session_free(bowie_session_t *session)
{
    if (session == NULL) {
        return;
    }

    OPENSSL_cleanse(session, sizeof(*session));
    free(session);
}


bowie_error_t bowie_session_new_from_key(
    const uint8_t *key, size_t key_len,
    const bowie_session_id_t *session_id,
    bowie_session_t **out)
{
    bowie_session_t *s;

    if (out == NULL || key == NULL || session_id == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }

    *out = NULL;

    if (key_len != BOWIE_SESSION_KEY_LEN) {
        return BOWIE_ERR_INVAL;
    }

    if (bowie_session_id_is_zero(session_id)) {
        return BOWIE_ERR_INVAL;
    }

    s = (bowie_session_t *)calloc(1, sizeof(*s));
    if (s == NULL) {
        return BOWIE_ERR_NOMEM;
    }

    /*
     * Copy the pre-derived key. The session layer does not
     * run a KDF on it; the caller has already done that.
     * The key is copied into the session's fixed-size
     * buffer; the caller's buffer is not retained.
     */
    memcpy(s->tx_key, key, BOWIE_SESSION_KEY_LEN);
    memcpy(s->rx_key, key, BOWIE_SESSION_KEY_LEN);
    s->tx_counter = 0;
    memcpy(&s->id, session_id, sizeof(s->id));

    *out = s;
    return BOWIE_OK;
}

bowie_error_t bowie_session_new_from_keys(
    const uint8_t *tx_key, const uint8_t *rx_key,
    const bowie_session_id_t *session_id, bowie_session_t **out)
{
    if (out == NULL || tx_key == NULL || rx_key == NULL || session_id == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }
    *out = NULL;
    if (bowie_session_id_is_zero(session_id)) return BOWIE_ERR_INVAL;

    bowie_session_t *s = (bowie_session_t *)calloc(1, sizeof(*s));
    if (s == NULL) return BOWIE_ERR_NOMEM;
    memcpy(s->tx_key, tx_key, BOWIE_SESSION_KEY_LEN);
    memcpy(s->rx_key, rx_key, BOWIE_SESSION_KEY_LEN);
    s->id = *session_id;
    *out = s;
    return BOWIE_OK;
}



/*
 * ============================================================================
 * QUERY
 * ============================================================================
 */

void bowie_session_get_id(const bowie_session_t *session,
                          bowie_session_id_t *out)
{
    if (session == NULL || out == NULL) {
        return;
    }

    memcpy(out, &session->id, sizeof(*out));
}

/*
 * ============================================================================
 * ENCRYPT
 * ============================================================================
 */

bowie_error_t bowie_session_encrypt(bowie_session_t *session,
                                    const void *plaintext,
                                    size_t plaintext_len,
                                    uint8_t *out,
                                    size_t out_cap,
                                    size_t *out_len)
{
    EVP_CIPHER_CTX *ctx;
    uint8_t         nonce[BOWIE_SESSION_NONCE_LEN];
    int             len;
    int             final_len;
    size_t          written;
    size_t          required;
    uint8_t         counter_bytes[BOWIE_SESSION_COUNTER_LEN];

    if (session == NULL || out == NULL || out_len == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }
    if (plaintext == NULL && plaintext_len > 0) {
        return BOWIE_ERR_NULL_ARG;
    }

    if (plaintext_len > SIZE_MAX - BOWIE_SESSION_OVERHEAD_LEN) {
        return BOWIE_ERR_TOO_LARGE;
    }

    if (session->tx_counter == UINT64_MAX) return BOWIE_ERR_TOO_LARGE;
    required = plaintext_len + BOWIE_SESSION_OVERHEAD_LEN;

    if (out_cap < required) {
        return BOWIE_ERR_TOO_SMALL;
    }

    if (plaintext_len > (size_t)INT_MAX) {
        return BOWIE_ERR_TOO_LARGE;
    }

    encode_counter(session->tx_counter, counter_bytes);
    make_nonce(session->tx_counter, nonce);

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        return BOWIE_ERR_CRYPTO;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return BOWIE_ERR_CRYPTO;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                             BOWIE_SESSION_NONCE_LEN, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return BOWIE_ERR_CRYPTO;
    }

    if (EVP_EncryptInit_ex(ctx, NULL, NULL, session->tx_key, nonce) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return BOWIE_ERR_CRYPTO;
    }

    memcpy(out, counter_bytes, sizeof(counter_bytes));
    len = 0;
    if (EVP_EncryptUpdate(ctx, NULL, &len, counter_bytes, sizeof(counter_bytes)) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return BOWIE_ERR_CRYPTO;
    }

    len = 0;

    if (plaintext_len > 0) {
        if (EVP_EncryptUpdate(ctx, out + BOWIE_SESSION_COUNTER_LEN, &len,
                               (const unsigned char *)plaintext,
                               (int)plaintext_len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return BOWIE_ERR_CRYPTO;
        }
    }

    written = (size_t)len;

    final_len = 0;
    if (EVP_EncryptFinal_ex(ctx, out + BOWIE_SESSION_COUNTER_LEN + written, &final_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return BOWIE_ERR_CRYPTO;
    }
    written += (size_t)final_len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG,
                             BOWIE_SESSION_TAG_LEN,
                             out + BOWIE_SESSION_COUNTER_LEN + written) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return BOWIE_ERR_CRYPTO;
    }
    written += BOWIE_SESSION_OVERHEAD_LEN;

    EVP_CIPHER_CTX_free(ctx);

    session->tx_counter += 1;

    *out_len = written;
    return BOWIE_OK;
}

/*
 * ============================================================================
 * DECRYPT
 * ============================================================================
 */

bowie_error_t bowie_session_decrypt(bowie_session_t *session,
                                    const void *ciphertext,
                                    size_t ciphertext_len,
                                    uint8_t *out,
                                    size_t out_cap,
                                    size_t *out_len)
{
    EVP_CIPHER_CTX *ctx;
    uint8_t         nonce[BOWIE_SESSION_NONCE_LEN];
    uint8_t         counter_bytes[BOWIE_SESSION_COUNTER_LEN];
    uint64_t        counter;
    int             len;
    int             final_len;
    size_t          written;
    size_t          ct_len;

    if (session == NULL || out == NULL || out_len == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }
    if (ciphertext == NULL && ciphertext_len > 0) {
        return BOWIE_ERR_NULL_ARG;
    }

    if (ciphertext_len < BOWIE_SESSION_OVERHEAD_LEN) {
        return BOWIE_ERR_CRYPTO;
    }

    ct_len = ciphertext_len - BOWIE_SESSION_OVERHEAD_LEN;
    memcpy(counter_bytes, ciphertext, sizeof(counter_bytes));
    counter = decode_counter(counter_bytes);
    if (!replay_candidate(session, counter)) return BOWIE_ERR_PERMISSION;

    if (out_cap < ct_len) {
        return BOWIE_ERR_TOO_SMALL;
    }

    if (ct_len > (size_t)INT_MAX) {
        return BOWIE_ERR_TOO_LARGE;
    }

    make_nonce(counter, nonce);

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        return BOWIE_ERR_CRYPTO;
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return BOWIE_ERR_CRYPTO;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                             BOWIE_SESSION_NONCE_LEN, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return BOWIE_ERR_CRYPTO;
    }

    if (EVP_DecryptInit_ex(ctx, NULL, NULL, session->rx_key, nonce) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return BOWIE_ERR_CRYPTO;
    }

    len = 0;
    if (EVP_DecryptUpdate(ctx, NULL, &len, counter_bytes, sizeof(counter_bytes)) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return BOWIE_ERR_CRYPTO;
    }

    len = 0;

    if (ct_len > 0) {
        if (EVP_DecryptUpdate(ctx, out, &len,
                               (const unsigned char *)ciphertext + BOWIE_SESSION_COUNTER_LEN,
                               (int)ct_len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return BOWIE_ERR_CRYPTO;
        }
    }

    written = (size_t)len;

    {
        const unsigned char *tag =
            (const unsigned char *)ciphertext + BOWIE_SESSION_COUNTER_LEN + ct_len;

        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG,
                                 BOWIE_SESSION_TAG_LEN,
                                 (void *)tag) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return BOWIE_ERR_CRYPTO;
        }
    }

    final_len = 0;
    if (EVP_DecryptFinal_ex(ctx, out + written, &final_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return BOWIE_ERR_CRYPTO;
    }
    written += (size_t)final_len;

    EVP_CIPHER_CTX_free(ctx);

    replay_commit(session, counter);

    *out_len = written;
    return BOWIE_OK;
}

/*
 * ============================================================================
 * END OF SECURITY SESSION IMPLEMENTATION
 * ============================================================================
 */
