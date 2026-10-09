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
 * BOWIE — CIPHER
 * ============================================================================
 *
 * Symmetric encryption and decryption.
 *
 * This header declares the cipher functions Bowie uses. The
 * implementation is backed by OpenSSL.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No asymmetric encryption. Public-key cryptography is in
 *     sign.h and keypair.h.
 *   - No key exchange. X25519 is in keypair.h.
 *   - No password-based encryption. Bowie does not store
 *     passwords. A caller that needs a KDF must use HMAC (in
 *     hash.h) or a dedicated KDF.
 *   - No streaming API. Every function encrypts or decrypts a
 *     complete buffer.
 *   - No allocation. Every function writes to a caller-supplied
 *     output buffer.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * Two cipher modes are provided:
 *
 *   - AES-256-GCM is the default. It provides both
 *     confidentiality and authentication. Every message is
 *     encrypted with a unique nonce; a nonce must never be
 *     reused with the same key.
 *
 *   - AES-256-CTR is provided for cases where the authentication
 *     is provided by an outer layer. It is faster than GCM and
 *     has no nonce length restriction beyond the AES block
 *     size.
 *
 * The caller supplies the key, the nonce, and the plaintext or
 * ciphertext. The key length is fixed at 32 bytes for both
 * modes. The nonce length is fixed at 12 bytes for GCM (the
 * standard) and 16 bytes for CTR (the AES block size).
 *
 * The GCM functions also take an additional authenticated data
 * (AAD) buffer. The AAD is not encrypted; it is covered by the
 * authentication tag. A caller that does not need AAD passes
 * NULL and 0.
 *
 * The output buffer for encryption must be at least the
 * plaintext length plus the tag length (16 bytes for GCM). A
 * caller that allocates exactly the plaintext length will
 * overflow the buffer.
 *
 * The decryption functions verify the tag. A caller must not
 * use the output buffer if the tag verification fails. The
 * functions write to the output buffer only after the tag is
 * verified.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <stdint.h>                    uint8_t
 *   <stddef.h>                    size_t
 *   "bowie/err.h"                 bowie_error_t
 *   "crypto/hash.h"               bowie_hash_sha256_t (for key types)
 *   <openssl/evp.h>               EVP_CIPHER_CTX
 * ============================================================================
 */

#ifndef BOWIE_CRYPTO_CIPHER_H
#define BOWIE_CRYPTO_CIPHER_H

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

#define BOWIE_CIPHER_KEY_LEN   32   /* AES-256 */
#define BOWIE_CIPHER_GCM_NONCE_LEN 12
#define BOWIE_CIPHER_CTR_NONCE_LEN 16
#define BOWIE_CIPHER_TAG_LEN   16

/*
 * ============================================================================
 * AES-256-GCM
 * ============================================================================
 *
 * Encrypt with an authenticated cipher. The output is the
 * ciphertext followed by a 16-byte authentication tag. The
 * caller must allocate at least plaintext_len + 16 bytes in
 * the output buffer.
 *
 * The nonce must be unique for every (key, message) pair. A
 * nonce reuse with the same key breaks both confidentiality
 * and authentication.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NULL_ARG if any required pointer is NULL.
 * Returns BOWIE_ERR_CRYPTO if the underlying library reports a
 *   failure.
 * Returns BOWIE_ERR_TOO_SMALL if the output buffer is not
 *   large enough. The output buffer size is passed as
 *   out_cap; the required size is plaintext_len + 16.
 */
bowie_error_t bowie_cipher_aes256_gcm_encrypt(
    const uint8_t key[BOWIE_CIPHER_KEY_LEN],
    const uint8_t nonce[BOWIE_CIPHER_GCM_NONCE_LEN],
    const void *aad, size_t aad_len,
    const void *plaintext, size_t plaintext_len,
    uint8_t *out, size_t out_cap,
    size_t *out_len);

/*
 * Decrypt an authenticated ciphertext.
 *
 * The input is the ciphertext followed by a 16-byte
 * authentication tag. The caller passes the total length in
 * ciphertext_len.
 *
 * The tag is verified before the plaintext is written to the
 * output buffer. If verification fails, the output buffer is
 * not modified.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NULL_ARG if any required pointer is NULL.
 * Returns BOWIE_ERR_CRYPTO if the tag verification fails or
 *   the underlying library reports a failure.
 * Returns BOWIE_ERR_TOO_SMALL if the output buffer is not
 *   large enough. The output buffer size is passed as
 *   out_cap; the required size is ciphertext_len - 16.
 */
bowie_error_t bowie_cipher_aes256_gcm_decrypt(
    const uint8_t key[BOWIE_CIPHER_KEY_LEN],
    const uint8_t nonce[BOWIE_CIPHER_GCM_NONCE_LEN],
    const void *aad, size_t aad_len,
    const void *ciphertext, size_t ciphertext_len,
    uint8_t *out, size_t out_cap,
    size_t *out_len);

/*
 * ============================================================================
 * AES-256-CTR
 * ============================================================================
 *
 * Encrypt or decrypt with a stream cipher. The output is the
 * same length as the input. A caller that needs authentication
 * must provide it at an outer layer.
 *
 * The nonce is 16 bytes (the AES block size). It is used as
 * the initial counter block. A caller must ensure the counter
 * does not wrap; for a 16-byte nonce and a 32-byte key, the
 * effective counter space is 2^128 blocks, which is beyond any
 * reasonable message length.
 *
 * The encrypt and decrypt functions are identical for CTR
 * mode: XOR with the keystream is its own inverse. Two
 * functions are provided for clarity; a caller can use either.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NULL_ARG if any required pointer is NULL.
 * Returns BOWIE_ERR_CRYPTO if the underlying library reports a
 *   failure.
 * Returns BOWIE_ERR_TOO_SMALL if the output buffer is not
 *   large enough. The output buffer size is passed as out_cap;
 *   the required size is input_len.
 */
bowie_error_t bowie_cipher_aes256_ctr_encrypt(
    const uint8_t key[BOWIE_CIPHER_KEY_LEN],
    const uint8_t nonce[BOWIE_CIPHER_CTR_NONCE_LEN],
    const void *plaintext, size_t plaintext_len,
    uint8_t *out, size_t out_cap,
    size_t *out_len);

bowie_error_t bowie_cipher_aes256_ctr_decrypt(
    const uint8_t key[BOWIE_CIPHER_KEY_LEN],
    const uint8_t nonce[BOWIE_CIPHER_CTR_NONCE_LEN],
    const void *ciphertext, size_t ciphertext_len,
    uint8_t *out, size_t out_cap,
    size_t *out_len);

#ifdef __cplusplus
}
#endif

#endif /* BOWIE_CRYPTO_CIPHER_H */
