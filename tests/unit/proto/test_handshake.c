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
 * BOWIE — PROTOCOL HANDSHAKE IMPLEMENTATION
 * ============================================================================
 *
 * The handshake state machine for the Bowie protocol.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No transport.
 *   - No allocation.
 *   - No permission.
 *   - No session key agreement.
 *   - No revocation check.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * The handshake is a two-message exchange:
 *
 *   Initiator                Responder
 *       |                        |
 *       |------ HELLO ---------->|
 *       |                        |
 *       |<----- HELLO_ACK -------|
 *       |                        |
 *     DONE                     DONE
 *
 * The HELLO payload is:
 *
 *   offset  size  field
 *   ------  ----  -----
 *        0    32  initiator public ID
 *       32    32  initiator nonce
 *       64    64  signature over the nonce
 *
 * The HELLO_ACK payload is:
 *
 *   offset  size  field
 *   ------  ----  -----
 *        0    32  responder public ID
 *       32    32  responder nonce
 *       64    64  signature over (initiator nonce || responder nonce)
 *
 * The signature is produced by the caller's sign callback and
 * verified by the caller's verify callback.
 *
 * ----------------------------------------------------------------------------
 * State transitions
 * ----------------------------------------------------------------------------
 *
 * Initiator:
 *   IDLE -> SENT_HELLO   on output HELLO
 *   SENT_HELLO -> DONE   on input HELLO_ACK
 *
 * Responder:
 *   IDLE -> SENT_HELLO   on input HELLO
 *   SENT_HELLO -> SENT_ACK on output HELLO_ACK
 *
 * A state that has no message to send returns BOWIE_OK with
 * out_has_msg set to 0. A state that cannot accept a message
 * returns BOWIE_ERR_STATE.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <stdint.h>                   uint8_t, uint32_t
 *   <stddef.h>                   size_t
 *   <string.h>                   memset, memcpy
 *   "bowie/types.h"              bowie_public_id_t, bowie_mtime_t
 *   "bowie/err.h"                error codes
 *   "proto/message.h"            the message type
 *   "proto/handshake.h"          the declarations
 * ============================================================================
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "bowie/types.h"
#include "bowie/err.h"
#include "proto/message.h"
#include "proto/handshake.h"

/*
 * ============================================================================
 * PAYLOAD LENGTHS
 * ============================================================================
 *
 * The HELLO payload is 32 + 32 + 64 = 128 bytes.
 * The HELLO_ACK payload is 32 + 32 + 64 = 128 bytes.
 */

#define HELLO_PAYLOAD_LEN \
    (BOWIE_PUBLIC_ID_LEN + BOWIE_PROTO_NONCE_LEN + BOWIE_PROTO_SIG_LEN)

#define HELLO_ACK_PAYLOAD_LEN \
    (BOWIE_PUBLIC_ID_LEN + BOWIE_PROTO_NONCE_LEN + BOWIE_PROTO_SIG_LEN)

/*
 * ============================================================================
 * LIFECYCLE
 * ============================================================================
 */

bowie_error_t bowie_proto_handshake_init(
    bowie_proto_handshake_t   *hs,
    bowie_proto_hs_role_t      role,
    const bowie_public_id_t   *local_id,
    bowie_proto_hs_sign_fn     sign,
    bowie_proto_hs_verify_fn   verify,
    void                      *ctx,
    bowie_mtime_t              timeout_ms,
    bowie_mtime_t              now_ms)
{
    if (hs == NULL || local_id == NULL ||
        sign == NULL || verify == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }
    if (role != BOWIE_PROTO_HS_INITIATOR &&
        role != BOWIE_PROTO_HS_RESPONDER) {
        return BOWIE_ERR_INVAL;
    }

    memset(hs, 0, sizeof(*hs));
    hs->state   = BOWIE_PROTO_HS_IDLE;
    hs->role    = role;
    hs->local_id = *local_id;

    hs->sign    = sign;
    hs->verify  = verify;
    hs->ctx     = ctx;

    hs->started_at_ms = now_ms;
    hs->timeout_ms    = (timeout_ms == 0u)
        ? BOWIE_PROTO_HS_DEFAULT_TIMEOUT_MS
        : timeout_ms;

    return BOWIE_OK;
}

void bowie_proto_handshake_clear(bowie_proto_handshake_t *hs)
{
    if (hs == NULL) {
        return;
    }

    bowie_proto_hs_sign_fn   sign    = hs->sign;
    bowie_proto_hs_verify_fn verify  = hs->verify;
    void                    *ctx     = hs->ctx;
    bowie_public_id_t        local   = hs->local_id;
    bowie_mtime_t            timeout = hs->timeout_ms;

    memset(hs, 0, sizeof(*hs));

    hs->sign         = sign;
    hs->verify       = verify;
    hs->ctx          = ctx;
    hs->local_id     = local;
    hs->timeout_ms   = timeout;
    hs->state        = BOWIE_PROTO_HS_IDLE;
}

/*
 * ============================================================================
 * OUTPUT
 * ============================================================================
 */

static bowie_error_t build_hello_payload(
    bowie_proto_handshake_t *hs,
    uint8_t                 *buf,
    size_t                   cap,
    size_t                  *out_len)
{
    if (cap < HELLO_PAYLOAD_LEN) {
        return BOWIE_ERR_TOO_SMALL;
    }

    memcpy(buf, hs->local_id.bytes, BOWIE_PUBLIC_ID_LEN);

    memcpy(buf + BOWIE_PUBLIC_ID_LEN,
           hs->local_nonce,
           BOWIE_PROTO_NONCE_LEN);

    bowie_error_t rc = hs->sign(
        hs->ctx,
        hs->local_nonce, BOWIE_PROTO_NONCE_LEN,
        buf + BOWIE_PUBLIC_ID_LEN + BOWIE_PROTO_NONCE_LEN);
    if (rc != BOWIE_OK) {
        return rc;
    }

    *out_len = HELLO_PAYLOAD_LEN;
    return BOWIE_OK;
}

static bowie_error_t build_hello_ack_payload(
    bowie_proto_handshake_t *hs,
    uint8_t                 *buf,
    size_t                   cap,
    size_t                  *out_len)
{
    if (cap < HELLO_ACK_PAYLOAD_LEN) {
        return BOWIE_ERR_TOO_SMALL;
    }

    memcpy(buf, hs->local_id.bytes, BOWIE_PUBLIC_ID_LEN);

    memcpy(buf + BOWIE_PUBLIC_ID_LEN,
           hs->local_nonce,
           BOWIE_PROTO_NONCE_LEN);

    uint8_t signed_msg[BOWIE_PROTO_NONCE_LEN * 2u];
    memcpy(signed_msg,
           hs->remote_nonce, BOWIE_PROTO_NONCE_LEN);
    memcpy(signed_msg + BOWIE_PROTO_NONCE_LEN,
           hs->local_nonce, BOWIE_PROTO_NONCE_LEN);

    bowie_error_t rc = hs->sign(
        hs->ctx,
        signed_msg, sizeof(signed_msg),
        buf + BOWIE_PUBLIC_ID_LEN + BOWIE_PROTO_NONCE_LEN);
    if (rc != BOWIE_OK) {
        return rc;
    }

    *out_len = HELLO_ACK_PAYLOAD_LEN;
    return BOWIE_OK;
}

bowie_error_t bowie_proto_handshake_output(
    bowie_proto_handshake_t *hs,
    bowie_proto_msg_t       *out_msg,
    int                     *out_has_msg)
{
    if (hs == NULL || out_msg == NULL || out_has_msg == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }

    *out_has_msg = 0;

    if (hs->state == BOWIE_PROTO_HS_DONE ||
        hs->state == BOWIE_PROTO_HS_FAILED) {
        return BOWIE_OK;
    }

    uint8_t *payload     = hs->out_payload;
    size_t   payload_cap = sizeof(hs->out_payload);
    size_t   payload_len = 0u;

    bowie_error_t rc = BOWIE_OK;

    if (hs->role == BOWIE_PROTO_HS_INITIATOR) {
        if (hs->state != BOWIE_PROTO_HS_IDLE) {
            /*
             * The initiator has already sent HELLO. There
             * is nothing more to send until HELLO_ACK
             * arrives.
             */
            return BOWIE_OK;
        }

        rc = build_hello_payload(hs, payload, payload_cap,
                                 &payload_len);
        if (rc != BOWIE_OK) {
            return rc;
        }

        memset(out_msg, 0, sizeof(*out_msg));
        out_msg->header.version = BOWIE_PROTO_VERSION;
        out_msg->header.type    = BOWIE_PROTO_MSG_HELLO;
        out_msg->header.length  = (uint32_t)payload_len;
        out_msg->payload.data   = payload;
        out_msg->payload.len    = payload_len;

        hs->state = BOWIE_PROTO_HS_SENT_HELLO;
        *out_has_msg = 1;
        return BOWIE_OK;
    }

    /*
     * Responder.
     */
    if (hs->state == BOWIE_PROTO_HS_IDLE) {
        /*
         * The responder has nothing to send until it has
         * received HELLO.
         */
        return BOWIE_OK;
    }

    if (hs->state != BOWIE_PROTO_HS_SENT_HELLO) {
        /*
         * The responder has already sent HELLO_ACK.
         */
        return BOWIE_OK;
    }

    rc = build_hello_ack_payload(hs, payload, payload_cap,
                                 &payload_len);
    if (rc != BOWIE_OK) {
        return rc;
    }

    memset(out_msg, 0, sizeof(*out_msg));
    out_msg->header.version = BOWIE_PROTO_VERSION;
    out_msg->header.type    = BOWIE_PROTO_MSG_HELLO_ACK;
    out_msg->header.length  = (uint32_t)payload_len;
    out_msg->payload.data   = payload;
    out_msg->payload.len    = payload_len;

    hs->state = BOWIE_PROTO_HS_SENT_ACK;
    *out_has_msg = 1;
    return BOWIE_OK;
}

/*
 * ============================================================================
 * INPUT
 * ============================================================================
 */

int bowie_proto_handshake_timed_out(
    const bowie_proto_handshake_t *hs,
    bowie_mtime_t                  now_ms)
{
    if (hs == NULL) {
        return 0;
    }
    if (hs->timeout_ms == 0u) {
        return 0;
    }
    if (now_ms < hs->started_at_ms) {
        return 0;
    }
    bowie_mtime_t elapsed = now_ms - hs->started_at_ms;
    return (elapsed >= hs->timeout_ms) ? 1 : 0;
}

static bowie_error_t handle_hello(
    bowie_proto_handshake_t *hs,
    const bowie_proto_msg_t *msg)
{
    if (msg->payload.len != HELLO_PAYLOAD_LEN) {
        return BOWIE_ERR_FORMAT;
    }

    const uint8_t *p = msg->payload.data;

    bowie_public_id_t remote_id;
    memcpy(remote_id.bytes, p, BOWIE_PUBLIC_ID_LEN);

    const uint8_t *nonce = p + BOWIE_PUBLIC_ID_LEN;
    const uint8_t *sig   = p + BOWIE_PUBLIC_ID_LEN +
                           BOWIE_PROTO_NONCE_LEN;

    if (!hs->verify(hs->ctx, &remote_id,
                    nonce, BOWIE_PROTO_NONCE_LEN, sig)) {
        hs->state = BOWIE_PROTO_HS_FAILED;
        return BOWIE_ERR_SIGN_INVALID;
    }

    hs->remote_id = remote_id;
    memcpy(hs->remote_nonce, nonce, BOWIE_PROTO_NONCE_LEN);
    hs->have_remote_nonce = 1;
    hs->have_local_nonce  = 1;

    /*
     * The responder has received HELLO. It can now send
     * HELLO_ACK. The state is set to SENT_HELLO so that the
     * output function knows it has work to do.
     */
    hs->state = BOWIE_PROTO_HS_SENT_HELLO;

    return BOWIE_OK;
}

static bowie_error_t handle_hello_ack(
    bowie_proto_handshake_t *hs,
    const bowie_proto_msg_t *msg)
{
    if (msg->payload.len != HELLO_ACK_PAYLOAD_LEN) {
        return BOWIE_ERR_FORMAT;
    }

    const uint8_t *p = msg->payload.data;

    bowie_public_id_t remote_id;
    memcpy(remote_id.bytes, p, BOWIE_PUBLIC_ID_LEN);

    const uint8_t *nonce = p + BOWIE_PUBLIC_ID_LEN;
    const uint8_t *sig   = p + BOWIE_PUBLIC_ID_LEN +
                           BOWIE_PROTO_NONCE_LEN;

    uint8_t signed_msg[BOWIE_PROTO_NONCE_LEN * 2u];
    memcpy(signed_msg,
           hs->local_nonce, BOWIE_PROTO_NONCE_LEN);
    memcpy(signed_msg + BOWIE_PROTO_NONCE_LEN,
           nonce, BOWIE_PROTO_NONCE_LEN);

    if (!hs->verify(hs->ctx, &remote_id,
                    signed_msg, sizeof(signed_msg), sig)) {
        hs->state = BOWIE_PROTO_HS_FAILED;
        return BOWIE_ERR_SIGN_INVALID;
    }

    hs->remote_id = remote_id;
    memcpy(hs->remote_nonce, nonce, BOWIE_PROTO_NONCE_LEN);
    hs->have_remote_nonce = 1;

    hs->state = BOWIE_PROTO_HS_DONE;
    return BOWIE_OK;
}

bowie_error_t bowie_proto_handshake_input(
    bowie_proto_handshake_t *hs,
    const bowie_proto_msg_t *msg,
    bowie_mtime_t            now_ms)
{
    if (hs == NULL || msg == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }
    if (hs->state == BOWIE_PROTO_HS_DONE ||
        hs->state == BOWIE_PROTO_HS_FAILED) {
        return BOWIE_ERR_STATE;
    }

    if (bowie_proto_handshake_timed_out(hs, now_ms)) {
        hs->state = BOWIE_PROTO_HS_FAILED;
        return BOWIE_ERR_TIMEOUT;
    }

    if (msg->header.type == BOWIE_PROTO_MSG_HELLO) {
        if (hs->role != BOWIE_PROTO_HS_RESPONDER) {
            return BOWIE_ERR_STATE;
        }
        if (hs->state != BOWIE_PROTO_HS_IDLE) {
            return BOWIE_ERR_STATE;
        }
        return handle_hello(hs, msg);
    }

    if (msg->header.type == BOWIE_PROTO_MSG_HELLO_ACK) {
        if (hs->role != BOWIE_PROTO_HS_INITIATOR) {
            return BOWIE_ERR_STATE;
        }
        if (hs->state != BOWIE_PROTO_HS_SENT_HELLO) {
            return BOWIE_ERR_STATE;
        }
        return handle_hello_ack(hs, msg);
    }

    return BOWIE_ERR_STATE;
}

/*
 * ============================================================================
 * QUERY
 * ============================================================================
 */

bowie_proto_hs_state_t bowie_proto_handshake_state(
    const bowie_proto_handshake_t *hs)
{
    if (hs == NULL) {
        return BOWIE_PROTO_HS_FAILED;
    }
    return hs->state;
}

bowie_error_t bowie_proto_handshake_remote_id(
    const bowie_proto_handshake_t *hs,
    bowie_public_id_t             *out_id)
{
    if (hs == NULL || out_id == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }
    if (bowie_public_id_is_zero(&hs->remote_id)) {
        return BOWIE_ERR_NOT_FOUND;
    }
    *out_id = hs->remote_id;
    return BOWIE_OK;
}

int bowie_proto_handshake_is_done(
    const bowie_proto_handshake_t *hs)
{
    if (hs == NULL) {
        return 0;
    }
    return (hs->state == BOWIE_PROTO_HS_DONE) ? 1 : 0;
}

int bowie_proto_handshake_is_failed(
    const bowie_proto_handshake_t *hs)
{
    if (hs == NULL) {
        return 1;
    }
    return (hs->state == BOWIE_PROTO_HS_FAILED) ? 1 : 0;
}

/*
 * ============================================================================
 * END OF FILE
 * ============================================================================
 */
