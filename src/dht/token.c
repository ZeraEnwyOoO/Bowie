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
 * BOWIE — DHT TOKEN IMPLEMENTATION
 * ============================================================================
 *
 * Token generation and validation for the DHT.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No allocation.
 *   - No network.
 *   - No storage.
 *   - No policy.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * The token is the SHA-1 of three values:
 *
 *   secret      32 bytes
 *   address     the peer's IPv4 address, 4 bytes
 *   port        the peer's port, 2 bytes, big-endian
 *
 * The three values are fed to the hash as one buffer. The
 * buffer is stack-allocated and is 38 bytes long. The buffer
 * is not secret; only the secret is. The address and port are
 * the peer's own values, which the peer already knows.
 *
 * The SHA-1 function is EVP_Digest from OpenSSL. The one-shot
 * call is used; it is simpler than the streaming interface
 * and it does not need a context. The one-shot call is
 * deprecated in OpenSSL 3; the replacement is EVP_Q_digest.
 * This file uses EVP_Digest for portability with OpenSSL 1.1
 * and 3. A future version can switch to EVP_Q_digest.
 *
 * The validation function computes the expected token twice,
 * once for each secret, and compares in constant time. The
 * constant-time comparison is a byte-wise XOR-accumulate. The
 * compiler cannot turn it into an early-exit comparison,
 * because the accumulator is a plain integer and the loop
 * runs to the end.
 *
 * The token length is fixed at 20 bytes. A token with a
 * different length is invalid. The check is made before the
 * comparison, because a length difference is not a secret.
 *
 * The state initialization reads 32 bytes from the platform
 * entropy source for each secret. The two reads are separate;
 * a failure on either one is reported.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <stdint.h>                   uint8_t, uint32_t
 *   <stddef.h>                   size_t
 *   <string.h>                   memcpy, memset
 *   <openssl/evp.h>              EVP_Digest, EVP_sha1
 *   "bowie/types.h"              bowie_addr_t, bowie_mtime_t
 *   "bowie/err.h"                error codes
 *   "dht/types.h"                bowie_dht_token_t
 *   "dht/token.h"                the declarations
 * ============================================================================
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include <openssl/evp.h>

#include "bowie/types.h"
#include "bowie/err.h"
#include "dht/types.h"
#include "dht/token.h"

/*
 * ============================================================================
 * INTERNAL — RANDOM SECRET
 * ============================================================================
 *
 * Fill a secret with bytes from the platform entropy source.
 *
 * The entropy source is the one in the core rand module. The
 * module is internal to the library; the token module is the
 * same library, so the include is allowed.
 *
 * A caller that does not have the core rand module linked
 * cannot use this module. That is the intended dependency.
 */

#include "core/internal/rand.h"

static bowie_error_t secret_random(bowie_dht_token_secret_t *s)
{
    memset(s, 0, sizeof(*s));
    bowie_error_t rc = bowie_rand_secure_bytes(s->bytes,
                                               sizeof(s->bytes));
    if (rc != BOWIE_OK) {
        return rc;
    }
    return BOWIE_OK;
}

/*
 * ============================================================================
 * INTERNAL — SECRET CHECK
 * ============================================================================
 *
 * True when the secret is not all zero.
 */

static int secret_is_set(const bowie_dht_token_secret_t *s)
{
    for (size_t i = 0u; i < sizeof(s->bytes); i++) {
        if (s->bytes[i] != 0u) {
            return 1;
        }
    }
    return 0;
}

/*
 * ============================================================================
 * INTERNAL — BUILD HASH INPUT
 * ============================================================================
 *
 * The hash input is the concatenation of the secret, the
 * IPv4 address, and the port in big-endian order.
 *
 * The address is four bytes. The port is two bytes. The
 * secret is BOWIE_DHT_TOKEN_SECRET_LEN bytes.
 *
 * The function writes the 38 bytes into a caller-supplied
 * buffer and returns the length.
 *
 * The peer address must be IPv4. The caller checks that
 * before calling this function.
 */

#define TOKEN_HASH_INPUT_LEN \
    (BOWIE_DHT_TOKEN_SECRET_LEN + 4u + 2u)

static size_t build_hash_input(const bowie_dht_token_secret_t *s,
                               const bowie_addr_t *addr,
                               uint8_t             *out)
{
    size_t pos = 0u;

    memcpy(out + pos, s->bytes, BOWIE_DHT_TOKEN_SECRET_LEN);
    pos += BOWIE_DHT_TOKEN_SECRET_LEN;

    memcpy(out + pos, addr->addr, 4u);
    pos += 4u;

    out[pos++] = (uint8_t)((addr->port >> 8) & 0xFFu);
    out[pos++] = (uint8_t)(addr->port & 0xFFu);

    return pos;
}

/*
 * ============================================================================
 * INTERNAL — COMPUTE TOKEN
 * ============================================================================
 *
 * Compute the 20-byte SHA-1 digest of the secret, address, and
 * port. The digest is written into out. The digest length is
 * fixed at 20.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_CRYPTO if OpenSSL fails.
 */

#define TOKEN_DIGEST_LEN 20u

static bowie_error_t compute_token(
    const bowie_dht_token_secret_t *s,
    const bowie_addr_t             *addr,
    uint8_t                         out[TOKEN_DIGEST_LEN])
{
    uint8_t input[TOKEN_HASH_INPUT_LEN];
    size_t  input_len = build_hash_input(s, addr, input);

    unsigned int out_len = 0u;
    int rc = EVP_Digest(input, input_len, out, &out_len,
                        EVP_sha1(), NULL);
    if (rc != 1) {
        return BOWIE_ERR_CRYPTO;
    }
    if (out_len != TOKEN_DIGEST_LEN) {
        return BOWIE_ERR_CRYPTO;
    }
    return BOWIE_OK;
}

/*
 * ============================================================================
 * INTERNAL — CONSTANT-TIME COMPARE
 * ============================================================================
 *
 * Compare two byte arrays in constant time. Returns 1 when
 * the arrays are equal, 0 otherwise.
 *
 * The comparison is a byte-wise XOR-accumulate. The result is
 * zero when the arrays are equal. The function does not exit
 * early; the loop runs to the end.
 */

static int constant_time_equal(const uint8_t *a,
                               const uint8_t *b,
                               size_t         n)
{
    uint8_t diff = 0u;
    for (size_t i = 0u; i < n; i++) {
        diff |= (uint8_t)(a[i] ^ b[i]);
    }
    return (diff == 0u) ? 1 : 0;
}

/*
 * ============================================================================
 * LIFECYCLE
 * ============================================================================
 */

bowie_error_t bowie_dht_token_state_init(
    bowie_dht_token_state_t *state,
    bowie_mtime_t            rotate_interval_ms,
    bowie_mtime_t            now_ms)
{
    if (state == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }

    memset(state, 0, sizeof(*state));

    bowie_error_t rc = secret_random(&state->current);
    if (rc != BOWIE_OK) {
        return rc;
    }

    rc = secret_random(&state->previous);
    if (rc != BOWIE_OK) {
        return rc;
    }

    state->last_rotate_ms     = now_ms;
    state->rotate_interval_ms = rotate_interval_ms;
    return BOWIE_OK;
}

void bowie_dht_token_state_clear(bowie_dht_token_state_t *state)
{
    if (state == NULL) {
        return;
    }
    memset(state, 0, sizeof(*state));
}

/*
 * ============================================================================
 * ROTATE
 * ============================================================================
 */

bowie_error_t bowie_dht_token_rotate(
    bowie_dht_token_state_t *state,
    bowie_mtime_t            now_ms)
{
    if (state == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }

    /*
     * The current secret becomes the previous. The previous
     * secret is discarded.
     */
    state->previous = state->current;

    bowie_error_t rc = secret_random(&state->current);
    if (rc != BOWIE_OK) {
        /*
         * The rotation failed. The current secret is now
         * zero. The state is not usable. The caller must
         * re-initialize it. The previous secret is still
         * valid, but the current one is not.
         */
        return rc;
    }

    state->last_rotate_ms = now_ms;
    return BOWIE_OK;
}

int bowie_dht_token_should_rotate(
    const bowie_dht_token_state_t *state,
    bowie_mtime_t                  now_ms)
{
    if (state == NULL) {
        return 0;
    }
    if (state->rotate_interval_ms == 0u) {
        return 0;
    }
    if (now_ms < state->last_rotate_ms) {
        /*
         * The clock moved backwards. Do not rotate; a
         * backward clock is not a reason to invalidate
         * every token.
         */
        return 0;
    }
    bowie_mtime_t elapsed = now_ms - state->last_rotate_ms;
    return (elapsed >= state->rotate_interval_ms) ? 1 : 0;
}

/*
 * ============================================================================
 * GENERATE
 * ============================================================================
 */

bowie_error_t bowie_dht_token_generate(
    const bowie_dht_token_state_t *state,
    const bowie_addr_t            *peer_addr,
    bowie_dht_token_t             *out_token)
{
    if (state == NULL || peer_addr == NULL || out_token == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }
    if (!secret_is_set(&state->current)) {
        return BOWIE_ERR_INVAL;
    }
    if (peer_addr->family != BOWIE_AF_INET) {
        return BOWIE_ERR_TYPE;
    }

    uint8_t digest[TOKEN_DIGEST_LEN];
    bowie_error_t rc = compute_token(&state->current,
                                     peer_addr, digest);
    if (rc != BOWIE_OK) {
        return rc;
    }

    bowie_dht_token_clear(out_token);
    memcpy(out_token->bytes, digest, TOKEN_DIGEST_LEN);
    out_token->len = TOKEN_DIGEST_LEN;
    return BOWIE_OK;
}

/*
 * ============================================================================
 * VALIDATE
 * ============================================================================
 */

int bowie_dht_token_validate(
    const bowie_dht_token_state_t *state,
    const bowie_addr_t            *peer_addr,
    const bowie_dht_token_t       *token)
{
    if (state == NULL || peer_addr == NULL || token == NULL) {
        return 0;
    }
    if (token->len != TOKEN_DIGEST_LEN) {
        return 0;
    }
    if (peer_addr->family != BOWIE_AF_INET) {
        return 0;
    }
    if (!secret_is_set(&state->current) &&
        !secret_is_set(&state->previous)) {
        return 0;
    }

    /*
     * Try the current secret first. A failure on the current
     * secret is not a reason to skip the previous one; the
     * two are independent.
     */
    if (secret_is_set(&state->current)) {
        uint8_t expected[TOKEN_DIGEST_LEN];
        bowie_error_t rc = compute_token(&state->current,
                                         peer_addr, expected);
        if (rc != BOWIE_OK) {
            return 0;
        }
        if (constant_time_equal(expected, token->bytes,
                                TOKEN_DIGEST_LEN)) {
            return 1;
        }
    }

    if (secret_is_set(&state->previous)) {
        uint8_t expected[TOKEN_DIGEST_LEN];
        bowie_error_t rc = compute_token(&state->previous,
                                         peer_addr, expected);
        if (rc != BOWIE_OK) {
            return 0;
        }
        if (constant_time_equal(expected, token->bytes,
                                TOKEN_DIGEST_LEN)) {
            return 1;
        }
    }

    return 0;
}

/*
 * ============================================================================
 * END OF FILE
 * ============================================================================
 */
