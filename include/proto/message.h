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
 * BOWIE — PROTOCOL MESSAGE
 * ============================================================================
 *
 * The wire message format for the Bowie protocol.
 *
 * Every message on the wire has a fixed-size header followed by
 * a variable-length payload. The header carries the version,
 * the message type, a flag word, the payload length, and a
 * message identifier.
 *
 * The header is always encoded in network byte order. The
 * payload is opaque to this layer; its meaning depends on the
 * message type.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No allocation. Every function writes into a
 *     caller-supplied buffer.
 *   - No I/O. Nothing here touches a socket.
 *   - No encryption. Encryption is the tunnel's concern; a
 *     message is encoded and decoded in the clear.
 *   - No compression.
 *   - No fragmentation. A message is a single unit; a message
 *     that does not fit in a buffer is rejected.
 *   - No policy. This layer does not decide which messages
 *     are allowed; that is the session and permission layer.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * The header is 12 bytes. It is deliberately small so that a
 * session keepalive is cheap and so that a small payload does
 * not pay a large overhead.
 *
 * Field layout:
 *
 *   offset  size  field
 *   ------  ----  -----
 *        0     1  version
 *        1     1  type
 *        2     2  flags
 *        4     4  length
 *        8     4  msg_id
 *
 * All multi-byte fields are big-endian. The version field
 * allows a future protocol to change the layout without a
 * flag day.
 *
 * The message identifier is chosen by the sender. It is used
 * to match a response to a request. It is not a security
 * token; it is a correlation value. The sender must ensure
 * that a request and its response use the same identifier.
 *
 * The length field is the length of the payload, not of the
 * whole message. A receiver that reads the header knows
 * exactly how many payload bytes to expect.
 *
 * A payload with length zero is valid. The type and the flags
 * carry the meaning of the message.
 *
 * The maximum payload length is a policy decision. This
 * header defines BOWIE_PROTO_MAX_PAYLOAD as the upper bound.
 * A message whose payload is longer than the bound is
 * rejected at encode time and at decode time.
 *
 * ----------------------------------------------------------------------------
 * Version
 * ----------------------------------------------------------------------------
 *
 * BOWIE_PROTO_VERSION is 1. A receiver that sees a different
 * version rejects the message with BOWIE_ERR_NOT_SUPPORTED.
 * A future version will add negotiation; v1 does not
 * negotiate.
 *
 * ----------------------------------------------------------------------------
 * Flags
 * ----------------------------------------------------------------------------
 *
 * The flag word is reserved for future use. v1 defines no
 * flags; a sender must set the flag word to zero and a
 * receiver must ignore it. A future version will define
 * flags for compression, fragmentation, and priority.
 *
 * A receiver that sees a non-zero flag word in v1 accepts the
 * message. The flags are ignored. This is deliberate: it
 * lets a future sender set a flag that v1 does not know, and
 * v1 still delivers the message. The alternative, rejecting
 * an unknown flag, would prevent a gradual deployment of a
 * new flag.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <stdint.h>                   uint8_t, uint16_t, uint32_t
 *   <stddef.h>                   size_t
 *   "bowie/types.h"              bowie_span_t
 *   "bowie/err.h"                error codes
 * ============================================================================
 */

#ifndef BOWIE_PROTO_MESSAGE_H
#define BOWIE_PROTO_MESSAGE_H

#include <stdint.h>
#include <stddef.h>

#include "bowie/types.h"
#include "bowie/err.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ============================================================================
 * VERSION
 * ============================================================================
 *
 * The protocol version this header describes. A message with a
 * different version is rejected.
 */

#define BOWIE_PROTO_VERSION 1u

/*
 * ============================================================================
 * HEADER SIZE
 * ============================================================================
 *
 * The fixed size of the message header, in bytes.
 */

#define BOWIE_PROTO_HEADER_LEN 12u

/*
 * ============================================================================
 * MAXIMUM PAYLOAD
 * ============================================================================
 *
 * The maximum payload length a single message can carry. A
 * message whose payload is longer than this is rejected.
 *
 * The value is chosen so that a message fits in a typical
 * UDP datagram without fragmentation on every platform Bowie
 * targets. A future version may add fragmentation; v1 does
 * not fragment.
 */

#define BOWIE_PROTO_MAX_PAYLOAD 1200u

/*
 * ============================================================================
 * MESSAGE TYPE
 * ============================================================================
 *
 * The type of a message. The type determines the meaning of
 * the payload.
 *
 * The values are grouped:
 *
 *     0        unknown
 *     1-9      handshake
 *    10-19     session
 *    20-29     signaling (NAT)
 *    30-39     permission
 *    40-49     data
 *    50-59     control
 *
 * A receiver that sees a type it does not know rejects the
 * message with BOWIE_ERR_NOT_SUPPORTED.
 */

typedef enum bowie_proto_msg_type {
    BOWIE_PROTO_MSG_UNKNOWN = 0,

    /* Handshake */
    BOWIE_PROTO_MSG_HELLO     = 1,
    BOWIE_PROTO_MSG_HELLO_ACK = 2,

    /* Session */
    BOWIE_PROTO_MSG_SESSION_OPEN  = 10,
    BOWIE_PROTO_MSG_SESSION_CLOSE = 11,

    /* Signaling (NAT) */
    BOWIE_PROTO_MSG_SIGNAL_OFFER     = 20,
    BOWIE_PROTO_MSG_SIGNAL_ANSWER    = 21,
    BOWIE_PROTO_MSG_SIGNAL_CANDIDATE = 22,

    /* Permission */
    BOWIE_PROTO_MSG_GRANT_VERIFY = 30,
    BOWIE_PROTO_MSG_GRANT_OK     = 31,
    BOWIE_PROTO_MSG_GRANT_DENY   = 32,

    /* Data */
    BOWIE_PROTO_MSG_DATA = 40,

    /* Control */
    BOWIE_PROTO_MSG_PING  = 50,
    BOWIE_PROTO_MSG_PONG  = 51,
    BOWIE_PROTO_MSG_ERROR = 52,
} bowie_proto_msg_type_t;

/*
 * ============================================================================
 * MESSAGE HEADER
 * ============================================================================
 *
 * The decoded form of a message header. The fields are in
 * host byte order.
 *
 * The struct is a value type. It is copied, not referenced.
 */

typedef struct bowie_proto_header {
    uint8_t  version;   /* protocol version */
    uint8_t  type;      /* bowie_proto_msg_type_t */
    uint16_t flags;     /* reserved; zero in v1 */
    uint32_t length;    /* payload length */
    uint32_t msg_id;    /* sender-chosen correlation id */
} bowie_proto_header_t;

/*
 * ============================================================================
 * MESSAGE
 * ============================================================================
 *
 * A decoded message: a header and a borrowed payload span.
 *
 * The payload span points into the input buffer. The caller
 * must keep the input buffer alive for as long as it uses the
 * message.
 */

typedef struct bowie_proto_msg {
    bowie_proto_header_t header;
    bowie_span_t         payload;
} bowie_proto_msg_t;

/*
 * ============================================================================
 * NAME HELPERS
 * ============================================================================
 */

/*
 * Return a stable, human-readable name for a message type.
 *
 * The returned pointer is to a static string and must not be
 * freed. The string is never NULL.
 */
const char *bowie_proto_msg_type_name(bowie_proto_msg_type_t t);

/*
 * True when the message type is a valid v1 type.
 *
 * A type that is not defined in v1 returns 0. A type that is
 * defined returns 1.
 */
int bowie_proto_msg_type_is_valid(bowie_proto_msg_type_t t);

/*
 * ============================================================================
 * ENCODE
 * ============================================================================
 */

/*
 * Encode a header into a caller-supplied buffer.
 *
 * The buffer must be at least BOWIE_PROTO_HEADER_LEN bytes.
 * The fields are written in network byte order.
 *
 * The version field is written from the header. The caller is
 * responsible for setting it; a header with an unset version
 * is rejected by the decoder.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NULL_ARG if buf or hdr is NULL.
 * Returns BOWIE_ERR_TOO_SMALL if cap is less than
 *   BOWIE_PROTO_HEADER_LEN.
 * Returns BOWIE_ERR_TOO_LARGE if hdr->length is greater than
 *   BOWIE_PROTO_MAX_PAYLOAD.
 */
bowie_error_t bowie_proto_header_encode(
    const bowie_proto_header_t *hdr,
    uint8_t                    *buf,
    size_t                      cap);

/*
 * Decode a header from a caller-supplied buffer.
 *
 * The buffer must be at least BOWIE_PROTO_HEADER_LEN bytes.
 * The fields are read from network byte order into host byte
 * order.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NULL_ARG if buf or hdr is NULL.
 * Returns BOWIE_ERR_TOO_SMALL if len is less than
 *   BOWIE_PROTO_HEADER_LEN.
 * Returns BOWIE_ERR_NOT_SUPPORTED if the version is not
 *   BOWIE_PROTO_VERSION.
 * Returns BOWIE_ERR_TOO_LARGE if the length field is greater
 *   than BOWIE_PROTO_MAX_PAYLOAD.
 */
bowie_error_t bowie_proto_header_decode(
    const uint8_t         *buf,
    size_t                 len,
    bowie_proto_header_t  *hdr);

/*
 * ============================================================================
 * MESSAGE HELPERS
 * ============================================================================
 */

/*
 * Encode a whole message into a caller-supplied buffer.
 *
 * The header is written first, then the payload. The
 * header's length field is set from the payload length; a
 * caller does not need to set it.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NULL_ARG if any required pointer is NULL.
 * Returns BOWIE_ERR_TOO_SMALL if the buffer is too small.
 * Returns BOWIE_ERR_TOO_LARGE if the payload is too long.
 */
bowie_error_t bowie_proto_msg_encode(
    const bowie_proto_msg_t *msg,
    uint8_t                 *buf,
    size_t                   cap,
    size_t                  *out_len);

/*
 * Decode a whole message from a caller-supplied buffer.
 *
 * The header is decoded first. The payload span points into
 * the input buffer.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NULL_ARG if any required pointer is NULL.
 * Returns BOWIE_ERR_TOO_SMALL if the buffer is too small for
 *   the header or for the declared payload.
 * Returns BOWIE_ERR_NOT_SUPPORTED if the version is not
 *   BOWIE_PROTO_VERSION.
 * Returns BOWIE_ERR_TOO_LARGE if the payload is too long.
 */
bowie_error_t bowie_proto_msg_decode(
    const uint8_t     *buf,
    size_t             len,
    bowie_proto_msg_t *msg);

/*
 * ============================================================================
 * END OF PROTOCOL MESSAGE
 * ============================================================================
 */

#ifdef __cplusplus
}
#endif

#endif /* BOWIE_PROTO_MESSAGE_H */
