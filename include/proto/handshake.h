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
 * A handshake is a two-message exchange:
 *
 *   Initiator                Responder
 *       |                        |
 *       |------ HELLO ---------->|
 *       |                        |
 *       |<----- HELLO_ACK -------|
 *       |                        |
 *     DONE                     DONE
 *
 * The handshake does not sign or verify. It calls the
 * caller's sign and verify callbacks. The caller owns the
 * crypto; the handshake owns the state machine.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No transport. The caller sends and receives messages.
 *   - No allocation. Every buffer is caller-supplied or
 *     lives inside the handshake struct.
 *   - No permission. The handshake proves identity; it does
 *     not check a grant.
 *   - No session key agreement. That is a later layer.
 *   - No revocation check.
 *
 * ----------------------------------------------------------------------------
 * Payload layouts
 * ----------------------------------------------------------------------------
 *
 * HELLO payload (128 bytes):
 *
 *   offset  size  field
 *   ------  ----  -----
 *        0    32  initiator public ID
 *       32    32  initiator nonce
 *       64    64  signature over the nonce
 *
 * HELLO_ACK payload (128 bytes):
 *
 *   offset  size  field
 *   ------  ----  -----
 *        0    32  responder public ID
 *       32    32  responder nonce
 *       64    64  signature over (initiator nonce || responder nonce)
 *
 * ----------------------------------------------------------------------------
 * Lifetime of the output payload
 * ----------------------------------------------------------------------------
 *
 * bowie_proto_handshake_output writes the payload into the
 * handshake's own scratch buffer (hs->out_payload). The span
 * placed into out_msg->payload points into that buffer. The
 * span stays valid until the next call to
 * bowie_proto_handshake_output or until
 * bowie_proto_handshake_clear. The caller must not free it.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <stdint.h>                   uint8_t, uint32_t
 *   <stddef.h>                   size_t
 *   "bowie/types.h"              bowie_public_id_t, bowie_mtime_t
 *   "bowie/err.h"                error codes
 *   "proto/message.h"            bowie_proto_msg_t, message types
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
 * CONSTANTS
 * ============================================================================
 */

/* Nonce length in bytes. */
#define BOWIE_PROTO_NONCE_LEN 32u

/* Signature length in bytes (Ed25519). */
#define BOWIE_PROTO_SIG_LEN 64u

/* Default handshake timeout, in milliseconds. */
#define BOWIE_PROTO_HS_DEFAULT_TIMEOUT_MS 30000u

/*
 * HELLO payload length:
 *   public ID (32) + nonce (32) + signature (64) = 128 bytes.
 */
#define BOWIE_PROTO_HELLO_PAYLOAD_LEN \
    (BOWIE_PUBLIC_ID_LEN + BOWIE_PROTO_NONCE_LEN + BOWIE_PROTO_SIG_LEN)

/*
 * HELLO_ACK payload length: same shape as HELLO.
 */
#define BOWIE_PROTO_HELLO_ACK_PAYLOAD_LEN \
    (BOWIE_PUBLIC_ID_LEN + BOWIE_PROTO_NONCE_LEN + BOWIE_PROTO_SIG_LEN)

/*
 * The scratch buffer inside the handshake. It must be large
 * enough for the largest payload the handshake ever writes.
 */
#define BOWIE_PROTO_HS_SCRATCH_LEN BOWIE_PROTO_HELLO_ACK_PAYLOAD_LEN

/*
 * ============================================================================
 * ROLE
 * ============================================================================
 */

typedef enum bowie_proto_hs_role {
    BOWIE_PROTO_HS_INITIATOR = 0,
    BOWIE_PROTO_HS_RESPONDER = 1,
} bowie_proto_hs_role_t;

/*
 * ============================================================================
 * STATE
 * ============================================================================
 *
 *   IDLE         nothing sent or received yet
 *   SENT_HELLO   initiator has sent HELLO, waiting for ACK
 *   SENT_ACK     responder has received HELLO and sent ACK
 *   DONE         handshake completed successfully
 *   FAILED       handshake failed; no further messages are sent
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
 * CALLBACKS
 * ============================================================================
 *
 * The sign callback writes BOWIE_PROTO_SIG_LEN bytes into
 * out_sig. It signs the data with the local private key.
 *
 * The verify callback returns non-zero when the signature is
 * valid for the given public ID and data.
 *
 * Both callbacks receive the ctx pointer passed to
 * bowie_proto_handshake_init.
 */

typedef bowie_error_t (*bowie_proto_hs_sign_fn)(
    void          *ctx,
    const uint8_t *data,
    size_t         len,
    uint8_t       *out_sig);

typedef int (*bowie_proto_hs_verify_fn)(
    void                   *ctx,
    const bowie_public_id_t *id,
    const uint8_t          *data,
    size_t                  len,
    const uint8_t          *sig);

/*
 * ============================================================================
 * HANDSHAKE
 * ============================================================================
 *
 * The handshake state. All fields are owned by the struct.
 * The struct is a value type; it can be copied but callbacks
 * and buffers travel with it.
 */

typedef struct bowie_proto_handshake {
    /* State machine */
    bowie_proto_hs_state_t   state;
    bowie_proto_hs_role_t    role;

    /* Identity */
    bowie_public_id_t        local_id;
    bowie_public_id_t        remote_id;

    /* Nonces */
    uint8_t                  local_nonce[BOWIE_PROTO_NONCE_LEN];
    uint8_t                  remote_nonce[BOWIE_PROTO_NONCE_LEN];
    int                      have_local_nonce;
    int                      have_remote_nonce;

    /* Callbacks */
    bowie_proto_hs_sign_fn   sign;
    bowie_proto_hs_verify_fn verify;
    void                    *ctx;

    /* Timing */
    bowie_mtime_t            started_at_ms;
    bowie_mtime_t            timeout_ms;

    /* Output scratch buffer */
    uint8_t                  out_payload[BOWIE_PROTO_HS_SCRATCH_LEN];
} bowie_proto_handshake_t;

/*
 * ============================================================================
 * LIFECYCLE
 * ============================================================================
 */

/*
 * Initialize a handshake.
 *
 * The caller supplies the role, the local public ID, the
 * sign and verify callbacks, a context pointer for those
 * callbacks, a timeout, and the current monotonic time.
 *
 * The handshake does not generate the local nonce. The
 * caller must write hs->local_nonce before the first output
 * call. A future version may generate it here.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NULL_ARG if hs, local_id, sign, or
 *   verify is NULL.
 * Returns BOWIE_ERR_INVAL if role is not INITIATOR or
 *   RESPONDER.
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
 * Reset a handshake to IDLE.
 *
 * The callbacks, the local ID, the local nonce, and the
 * timeout are preserved. The state, the remote ID, the
 * remote nonce, and the scratch buffer are cleared.
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
 * Produce the next message to send.
 *
 * On success, when the handshake has a message to send,
 * *out_has_msg is set to 1 and out_msg is filled. The
 * payload span in out_msg points into hs->out_payload and
 * stays valid until the next output call or until the
 * handshake is cleared.
 *
 * When there is nothing to send, *out_has_msg is set to 0
 * and out_msg is untouched.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NULL_ARG if any pointer is NULL.
 * Returns BOWIE_ERR_STATE if the state does not allow
 *   output.
 * Returns any error from the sign callback.
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
 * Process an incoming message.
 *
 * HELLO is accepted only by a RESPONDER in the IDLE state.
 * HELLO_ACK is accepted only by an INITIATOR in the
 * SENT_HELLO state.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NULL_ARG if hs or msg is NULL.
 * Returns BOWIE_ERR_STATE if the message type does not fit
 *   the current state.
 * Returns BOWIE_ERR_FORMAT if the payload length is wrong.
 * Returns BOWIE_ERR_SIGN_INVALID if verification fails.
 * Returns BOWIE_ERR_TIMEOUT if the handshake has timed out.
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
 * Return the current handshake state.
 *
 * Returns BOWIE_PROTO_HS_FAILED for NULL.
 */
bowie_proto_hs_state_t bowie_proto_handshake_state(
    const bowie_proto_handshake_t *hs);

/*
 * Copy the remote public ID into out_id.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NULL_ARG if either pointer is NULL.
 * Returns BOWIE_ERR_NOT_FOUND when the remote ID is not yet
 *   known.
 */
bowie_error_t bowie_proto_handshake_remote_id(
    const bowie_proto_handshake_t *hs,
    bowie_public_id_t             *out_id);

/*
 * True when the state is DONE.
 *
 * Returns 0 for NULL.
 */
int bowie_proto_handshake_is_done(
    const bowie_proto_handshake_t *hs);

/*
 * True when the state is FAILED.
 *
 * Returns 1 for NULL.
 */
int bowie_proto_handshake_is_failed(
    const bowie_proto_handshake_t *hs);

/*
 * True when the handshake has exceeded its timeout.
 *
 * Returns 0 when hs is NULL, when the timeout is zero, or
 * when the clock has moved backwards.
 */
int bowie_proto_handshake_timed_out(
    const bowie_proto_handshake_t *hs,
    bowie_mtime_t                  now_ms);

/*
 * ============================================================================
 * END OF PROTOCOL HANDSHAKE
 * ============================================================================
 */

#ifdef __cplusplus
}
#endif

#endif /* BOWIE_PROTO_HANDSHAKE_H */
