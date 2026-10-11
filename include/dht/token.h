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
 * BOWIE — DHT TOKEN
 * ============================================================================
 *
 * Token generation and validation for the DHT.
 *
 * A token is a short opaque value that a node hands out and
 * later checks. It is the Mainline DHT's defense against IP
 * spoofing and against a peer that announces an address it
 * cannot receive at.
 *
 * The token is stateless. The node does not remember which
 * token it handed to which peer. Instead, the token is a
 * function of a secret and the peer's address. The node
 * remembers two secrets: the current one and the previous
 * one. A token generated with either secret is accepted. The
 * two secrets give the token a lifetime of up to twice the
 * rotation interval.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No allocation. The token state is a value type.
 *   - No network. Nothing here sends a packet.
 *   - No storage. The token state does not remember
 *     individual tokens.
 *   - No policy on when to require a token. The DHT engine
 *     decides when to call the generate and validate
 *     functions.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * The token is the SHA-1 of three values:
 *
 *   secret      32 bytes, random, rotated periodically
 *   address     the peer's IPv4 address, 4 bytes
 *   port        the peer's port, 2 bytes, big-endian
 *
 * The port is included so that a peer that announces from a
 * different port than the one it queried from is rejected.
 * The Mainline DHT does not always include the port; this
 * implementation does, because the port is part of the
 * address a peer must be able to receive at.
 *
 * The token is 20 bytes: the size of a SHA-1 digest. The
 * token type in dht/types.h allows up to 32 bytes; this
 * module produces exactly 20.
 *
 * The secret is generated from the platform entropy source
 * when the token state is initialized. The secret is rotated
 * by the DHT engine, not by this module. The engine decides
 * the rotation policy; the module provides the function.
 *
 * The token state holds two secrets: "current" and
 * "previous". A rotate moves the current secret to the
 * previous slot and generates a new current. A token is
 * accepted when it matches either secret.
 *
 * The rotation interval is stored in the state. A caller
 * that never rotates has a token with infinite lifetime; the
 * DHT engine is expected to rotate on a schedule.
 *
 * The validation function computes the token twice, once for
 * each secret, and compares the result to the presented
 * token. The comparison is constant-time to avoid a timing
 * side channel. The function returns 1 when the token is
 * valid and 0 otherwise.
 *
 * The state is not thread-safe. The DHT engine serializes
 * access.
 *
 * ----------------------------------------------------------------------------
 * Security
 * ----------------------------------------------------------------------------
 *
 * The token is not a cryptographic signature. It is a
 * challenge that a peer can answer only if it can receive at
 * the address it claims. An attacker who can observe the
 * token in transit can replay it from the same address; this
 * is the same limitation as the Mainline DHT, and the same
 * reason the token is short-lived.
 *
 * The secret must be unpredictable. This module generates it
 * from the platform entropy source. A caller that supplies
 * its own secret must use a cryptographic source.
 *
 * The secret is stored in the token state as plain bytes.
 * The state is a value type; a copy of the state is a copy
 * of the secret. A caller that passes the state by value
 * must be aware that the secret is copied too.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <stdint.h>                   uint8_t, uint32_t
 *   <stddef.h>                   size_t
 *   "bowie/types.h"              bowie_addr_t, bowie_mtime_t
 *   "bowie/err.h"                error codes
 *   "dht/types.h"                bowie_dht_token_t
 * ============================================================================
 */

#ifndef BOWIE_DHT_TOKEN_H
#define BOWIE_DHT_TOKEN_H

#include <stdint.h>
#include <stddef.h>

#include "bowie/types.h"
#include "bowie/err.h"
#include "dht/types.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ============================================================================
 * LIMITS
 * ============================================================================
 *
 * BOWIE_DHT_TOKEN_SECRET_LEN is the size of one secret. It is
 * 32 bytes, the size of a SHA-256 digest, even though the
 * token itself is a SHA-1 digest. The extra bytes are not
 * needed for SHA-1; they are a margin in case the hash
 * changes.
 *
 * BOWIE_DHT_TOKEN_LIFETIME_S is the default lifetime of a
 * token. The actual lifetime depends on the rotation
 * interval; the constant is a suggested value for the
 * rotation policy.
 */

#define BOWIE_DHT_TOKEN_SECRET_LEN  32
#define BOWIE_DHT_TOKEN_LIFETIME_S  600   /* 10 minutes */

/*
 * ============================================================================
 * SECRET
 * ============================================================================
 *
 * One secret. The secret is a value type. It is generated by
 * the platform entropy source when the token state is
 * initialized, and by the rotate function on each rotation.
 *
 * An all-zero secret is unset. The token functions reject an
 * unset secret.
 */

typedef struct bowie_dht_token_secret {
    uint8_t bytes[BOWIE_DHT_TOKEN_SECRET_LEN];
} bowie_dht_token_secret_t;

/*
 * ============================================================================
 * TOKEN STATE
 * ============================================================================
 *
 * The state of the token generator. It holds the current
 * secret, the previous secret, the time of the last rotation,
 * and the rotation interval.
 *
 * The state is a value type. It is stored in the DHT engine
 * and copied with the engine.
 *
 * The two secrets give a token a lifetime of up to twice the
 * rotation interval. A token generated just before a rotation
 * is accepted until the rotation after next.
 */

typedef struct bowie_dht_token_state {
    bowie_dht_token_secret_t current;
    bowie_dht_token_secret_t previous;
    bowie_mtime_t            last_rotate_ms;
    bowie_mtime_t            rotate_interval_ms;
} bowie_dht_token_state_t;

/*
 * ============================================================================
 * LIFECYCLE
 * ============================================================================
 */

/*
 * Initialize a token state.
 *
 * The current and previous secrets are generated from the
 * platform entropy source. The last-rotate time is set to
 * now. The rotation interval is copied.
 *
 * A rotation interval of 0 means "never rotate". The token
 * then has an infinite lifetime; the caller is responsible
 * for choosing a policy that fits its threat model.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NULL_ARG if state is NULL.
 * Returns a CRYPTO-class error if the entropy source fails.
 */
bowie_error_t bowie_dht_token_state_init(
    bowie_dht_token_state_t *state,
    bowie_mtime_t            rotate_interval_ms,
    bowie_mtime_t            now_ms);

/*
 * Reset a token state to the unset state.
 *
 * The secrets are zeroed. The timestamps are zeroed. The
 * rotation interval is zeroed.
 *
 * A state that has been reset must be re-initialized before
 * it is used.
 *
 * Passing NULL is a no-op.
 */
void bowie_dht_token_state_clear(bowie_dht_token_state_t *state);

/*
 * ============================================================================
 * ROTATE
 * ============================================================================
 */

/*
 * Rotate the secrets.
 *
 * The current secret becomes the previous secret. A new
 * current secret is generated from the platform entropy
 * source. The last-rotate time is set to now.
 *
 * The caller decides when to rotate. A typical policy is to
 * rotate when the current time minus the last-rotate time is
 * greater than or equal to the rotation interval.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NULL_ARG if state is NULL.
 * Returns a CRYPTO-class error if the entropy source fails.
 */
bowie_error_t bowie_dht_token_rotate(
    bowie_dht_token_state_t *state,
    bowie_mtime_t            now_ms);

/*
 * True when the state should rotate at the given time.
 *
 * A state with a rotation interval of 0 never rotates.
 *
 * Returns 0 for NULL.
 */
int bowie_dht_token_should_rotate(
    const bowie_dht_token_state_t *state,
    bowie_mtime_t                  now_ms);

/*
 * ============================================================================
 * GENERATE
 * ============================================================================
 */

/*
 * Generate a token for a peer address.
 *
 * The token is the SHA-1 of the current secret, the peer's
 * IPv4 address, and the peer's port in big-endian order.
 *
 * The token is written through out_token. The token's length
 * is set to 20 (the SHA-1 digest size).
 *
 * The peer address must be IPv4. An IPv6 address is rejected
 * with BOWIE_ERR_TYPE. IPv6 support is a separate decision;
 * see the design notes.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NULL_ARG if any pointer is NULL.
 * Returns BOWIE_ERR_INVAL if the state has not been
 *   initialized (the current secret is all zero).
 * Returns BOWIE_ERR_TYPE if the peer address is not IPv4.
 */
bowie_error_t bowie_dht_token_generate(
    const bowie_dht_token_state_t *state,
    const bowie_addr_t            *peer_addr,
    bowie_dht_token_t             *out_token);

/*
 * ============================================================================
 * VALIDATE
 * ============================================================================
 */

/*
 * Validate a token for a peer address.
 *
 * The function computes the expected token twice: once with
 * the current secret and once with the previous secret. It
 * compares the presented token to each expected token in
 * constant time. A match with either secret is a valid
 * token.
 *
 * A token with a length other than 20 is invalid.
 *
 * Returns 1 when the token is valid.
 * Returns 0 when the token is invalid, when any pointer is
 *   NULL, when the state has not been initialized, or when
 *   the peer address is not IPv4.
 */
int bowie_dht_token_validate(
    const bowie_dht_token_state_t *state,
    const bowie_addr_t            *peer_addr,
    const bowie_dht_token_t       *token);

/*
 * ============================================================================
 * END OF DHT TOKEN
 * ============================================================================
 */

#ifdef __cplusplus
}
#endif

#endif /* BOWIE_DHT_TOKEN_H */
