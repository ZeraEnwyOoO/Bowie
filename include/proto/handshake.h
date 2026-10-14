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
 * BOWIE — PROTOCOL HANDSHAKE
 * ============================================================================
 *
 * The handshake state machine for the Bowie protocol.
 *
 * A handshake establishes a session between two peers. It runs
 * before any session data flows. The handshake exchanges the
 * peers' public identities and proves that each peer holds the
 * private key for the identity it claims.
 *
 * The handshake is a small state machine. The caller drives it:
 *
 *   - It creates a handshake with bowie_proto_handshake_new.
 *   - It feeds incoming messages with
 *     bowie_proto_handshake_input.
 *   - It gets outgoing messages with
 *     bowie_proto_handshake_output.
 *   - It reads the result with
 *     bowie_proto_handshake_state.
 *   - It destroys the handshake with
 *     bowie_proto_handshake_free.
 *
 * The state machine does not send or receive packets. The caller
 * owns the transport.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No transport. The caller sends and receives.
 *   - No allocation on the caller's behalf. The handshake state
 *     is a fixed-size value type.
 *   - No permission. The handshake proves identity; it does not
 *     decide whether the peer is allowed. That is the session
 *     and permission layer.
 *   - No session key agreement. The handshake proves identity;
 *     the session layer agrees the keys.
 *   - No revocation check. The handshake proves the peer holds
 *     a key; whether that key is still trusted is a separate
 *     question.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * The handshake is a two-message exchange:
 *
 *   1. The initiator sends HELLO, which carries its public ID,
 *      a nonce, and a signature over the nonce.
 *
 *   2. The responder checks the signature, then sends HELLO_ACK,
 *      which carries its public ID, its own nonce, and a
 *      signature over both nonces.
 *
 * The initiator checks the responder's signature. Both peers
 * now know each other's public ID and have proof that the other
 * holds the corresponding private key.
 *
 * The handshake has four states:
 *
 *   IDLE        nothing has happened
 *   SENT_HELLO  the initiator has sent HELLO, no response yet
 *   SENT_ACK    the responder has sent HELLO_ACK, no final
 *               message yet
 *   DONE        the handshake succeeded
 *   FAILED      the handshake failed
 *
 * The state machine is deterministic. A message that does not
 * fit the current state is rejected with BOWIE_ERR_STATE.
 *
 * The handshake carries two nonces: one from the initiator and
 * one from the responder. The responder's signature covers both
 * nonces, so the handshake is bound to the exchange. A replayed
 * HELLO_ACK does not verify because the initiator's nonce is
 * different.
 *
 * A handshake has a timeout. The caller passes the current
 * time to the input function; a handshake that has not finished
 * by the timeout is failed.
 *
 * ----------------------------------------------------------------------------
 * Identity
 * ----------------------------------------------------------------------------
 *
 * A public ID is a 32-byte Ed25519 public key. The private key
 * is not part of the handshake; the handshake holds a public ID
 * and a callback that signs.
 *
 * The signing callback is provided by the caller. The handshake
 * calls it when it needs a signature. The callback writes the
 * signature into a caller-supplied buffer. The private key
 * never enters the handshake.
 *
 * The verification callback is also provided by the caller. It
 * takes a public ID and a message and returns whether the
 * signature is valid. The handshake does not know how to verify
 * a signature; it asks the caller.
 *
 * This split keeps the handshake free of any dependency on the
 * crypto layer. A caller that uses the crypto layer provides
 * signing and verification callbacks that call into it.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <stdint.h>                   uint8_t, uint32_t
 *   <stddef.h>                   size_t
 *   "bowie/types.h"              bowie_public_id_t, bowie_mtime_t
 *   "bowie/err.h"                error codes
 *   "proto/message.h"            the message type
 * ============================================================================
 */

#ifndef BOWIE_PROTO_HANDSHAKE_H
#define BOWIE_PROTO_HANDSHAKE_H

#include <stdint.h>
#include <stddef.h>

#include "bowie/types.h"
#include "bowie/err.h"
#include "proto/message.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ============================================================================
 * LIMITS
 * ============================================================================
 *
 * BOWIE_PROTO_NONCE_LEN is the length of the handshake nonce.
 * 32 bytes is a comfortable margin over the 16 bytes that
 * would be enough for a unique value.
 *
 * BOWIE_PROTO_SIG_LEN is the length of an Ed25519 signature.
 */

#define BOWIE_PROTO_NONCE_LEN 32
#define BOWIE_PROTO_SIG_LEN   64

/*
 * ============================================================================
 * STATE
 * ============================================================================
 */

typedef enum bowie_proto_hs_state {
    BOWIE_PROTO_HS_IDLE       = 0,
    BOWIE_PROTO_HS_SENT_HELLO = 1,
    BOWIE_PROTO_HS_SENT_ACK   = 2,
    BOWIE_PROTO_HS_DONE       = 3,
    BOWIE_PROTO_HS_FAILED     = 4,
} bowie_proto_hs_state_t;

/*
 * ============================================================================
 * ROLE
 * ============================================================================
 *
 * The role a handshake plays. The initiator sends HELLO first;
 * the responder waits for HELLO and then sends HELLO_ACK.
 */

typedef enum bowie_proto_hs_role {
    BOWIE_PROTO_HS_INITIATOR = 0,
    BOWIE_PROTO_HS_RESPONDER = 1,
} bowie_proto_hs_role_t;

/*
 * ============================================================================
 * SIGN AND VERIFY CALLBACKS
 * ============================================================================
 *
 * The caller supplies these callbacks. The handshake calls
 * them when it needs a signature or a verification.
 */

/*
 * Sign a message with the local private key.
 *
 * The signature is written into sig, which has room for
 * BOWIE_PROTO_SIG_LEN bytes.
 *
 * Returns BOWIE_OK on success.
 * Returns an error if the signature cannot be produced.
 */
typedef bowie_error_t (*bowie_proto_hs_sign_fn)(
    void *ctx,
    const uint8_t *msg, size_t msg_len,
    uint8_t *sig);

/*
 * Verify a signature with a peer's public ID.
 *
 * Returns 1 when the signature is valid, 0 when it is not.
 */
typedef int (*bowie_proto_hs_verify_fn)(
    void *ctx,
    const bowie_public_id_t *id,
    const uint8_t *msg, size_t msg_len,
    const uint8_t *sig);

/*
 * ============================================================================
 * HANDSHAKE
 * ============================================================================
 */

typedef struct bowie_proto_handshake {
    bowie_proto_hs_state_t  state;
    bowie_proto_hs_role_t   role;

    bowie_public_id_t       local_id;
    bowie_public_id_t       remote_id;

    uint8_t                 local_nonce[BOWIE_PROTO_NONCE_LEN];
    uint8_t                 remote_nonce[BOWIE_PROTO_NONCE_LEN];
    int                     have_local_nonce;
    int                     have_remote_nonce;

    bowie_mtime_t           started_at_ms;
    bowie_mtime_t           timeout_ms;

    bowie_proto_hs_sign_fn   sign;
    bowie_proto_hs_verify_fn verify;
    void                    *ctx;
} bowie_proto_handshake_t;

/*
 * ============================================================================
 * LIFECYCLE
 * ============================================================================
 */

/*
 * Initialize a handshake.
 *
 * The role selects initiator or responder. The local ID is the
 * caller's public ID. The sign and verify callbacks are
 * required; a NULL callback is a programming error.
 *
 * timeout_ms is the handshake timeout. A value of 0 means the
 * default (BOWIE_PROTO_HS_DEFAULT_TIMEOUT_MS).
 *
 * now_ms is the current monotonic time.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NULL_ARG if hs, local_id, sign, or verify
 *   is NULL.
 * Returns BOWIE_ERR_INVAL if the role is not a known value.
 */
bowie_error_t bowie_proto_handshake_init(
    bowie_proto_handshake_t   *hs,
    bowie_proto_hs_role_t      role,
    const bowie_public_id_t   *local_id,
    bowie_proto_hs_sign_fn     sign,
    bowie_proto_hs_verify_fn   verify,
    void                      *ctx,
    bowie_mtime_t              timeout_ms,
    bowie_mtime_t              now_ms);

/*
 * Reset a handshake to the idle state.
 *
 * The callbacks and the local ID are not changed; only the
 * state, the nonces, and the remote ID are reset.
 *
 * Passing NULL is a no-op.
 */
void bowie_proto_handshake_clear(bowie_proto_handshake_t *hs);

/*
 * ============================================================================
 * OUTPUT
 * ============================================================================
 */

/*
 * Get the next outgoing message, if any.
 *
 * The function checks the current state and produces the
 * message that the state requires:
 *
 *   INITIATOR, IDLE        -> HELLO
 *   RESPONDER, IDLE        -> no message
 *   RESPONDER, SENT_HELLO  -> HELLO_ACK
 *   any, DONE              -> no message
 *   any, FAILED            -> no message
 *
 * When a message is produced, the function writes it through
 * out_msg and sets out_has_msg to 1. When no message is due,
 * out_has_msg is set to 0 and out_msg is unchanged.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NULL_ARG if hs, out_msg, or out_has_msg is
 *   NULL.
 * Returns BOWIE_ERR_STATE if the current state cannot produce a
 *   message.
 */
bowie_error_t bowie_proto_handshake_output(
    bowie_proto_handshake_t *hs,
    bowie_proto_msg_t       *out_msg,
    int                     *out_has_msg);

/*
 * ============================================================================
 * INPUT
 * ============================================================================
 */

/*
 * Feed an incoming message to the handshake.
 *
 * The function checks the message type against the current
 * state and advances the state machine.
 *
 * A message that does not fit the state is rejected with
 * BOWIE_ERR_STATE. A message whose signature does not verify
 * moves the handshake to the FAILED state and returns
 * BOWIE_ERR_SIGN_INVALID.
 *
 * A handshake whose timeout has elapsed moves to the FAILED
 * state and returns BOWIE_ERR_TIMEOUT.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NULL_ARG if hs or msg is NULL.
 * Returns BOWIE_ERR_STATE if the message type does not fit the
 *   current state.
 * Returns BOWIE_ERR_SIGN_INVALID if a signature does not
 *   verify.
 * Returns BOWIE_ERR_TIMEOUT if the handshake has timed out.
 * Returns BOWIE_ERR_FORMAT if the message payload is malformed.
 */
bowie_error_t bowie_proto_handshake_input(
    bowie_proto_handshake_t *hs,
    const bowie_proto_msg_t *msg,
    bowie_mtime_t            now_ms);

/*
 * ============================================================================
 * QUERY
 * ============================================================================
 */

/*
 * Return the current state.
 *
 * Returns BOWIE_PROTO_HS_FAILED for a NULL handshake.
 */
bowie_proto_hs_state_t bowie_proto_handshake_state(
    const bowie_proto_handshake_t *hs);

/*
 * Return the remote public ID, when known.
 *
 * A handshake that has not received a valid message from the
 * remote peer has no remote ID. The function writes the remote
 * ID through out_id only when it is known.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NULL_ARG if hs or out_id is NULL.
 * Returns BOWIE_ERR_NOT_FOUND if the remote ID is not known.
 */
bowie_error_t bowie_proto_handshake_remote_id(
    const bowie_proto_handshake_t *hs,
    bowie_public_id_t             *out_id);

/*
 * True when the handshake is done.
 *
 * Returns 0 for NULL.
 */
int bowie_proto_handshake_is_done(
    const bowie_proto_handshake_t *hs);

/*
 * True when the handshake has failed.
 *
 * Returns 1 for NULL.
 */
int bowie_proto_handshake_is_failed(
    const bowie_proto_handshake_t *hs);

/*
 * True when the handshake has timed out at the given time.
 *
 * Returns 0 for NULL.
 */
int bowie_proto_handshake_timed_out(
    const bowie_proto_handshake_t *hs,
    bowie_mtime_t                  now_ms);

/*
 * ============================================================================
 * DEFAULTS
 * ============================================================================
 */

#define BOWIE_PROTO_HS_DEFAULT_TIMEOUT_MS 10000u  /* 10 s */

/*
 * ============================================================================
 * END OF PROTOCOL HANDSHAKE
 * ============================================================================
 */

#ifdef __cplusplus
}
#endif

#endif /* BOWIE_PROTO_HANDSHAKE_H */
