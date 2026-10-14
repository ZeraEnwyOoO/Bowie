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
 * BOWIE — PROTOCOL MESSAGE IMPLEMENTATION
 * ============================================================================
 *
 * Header and message encoding and decoding for the Bowie
 * protocol.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No allocation.
 *   - No I/O.
 *   - No encryption.
 *   - No compression.
 *   - No fragmentation.
 *   - No policy.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * The header is 12 bytes. Every multi-byte field is big-endian
 * (network byte order). The encoder and decoder use the
 * helpers from bowie/core/internal/endian.h so that the byte
 * order handling lives in one place.
 *
 * The encoder writes the header into a caller-supplied buffer.
 * The decoder reads a header from a caller-supplied buffer.
 *
 * The whole-message encoder writes the header and then the
 * payload, and sets the header's length field from the payload
 * length. The whole-message decoder decodes the header and
 * then points the payload span into the input buffer.
 *
 * A message whose payload is longer than
 * BOWIE_PROTO_MAX_PAYLOAD is rejected at encode time and at
 * decode time.
 *
 * A message whose version is not BOWIE_PROTO_VERSION is
 * rejected at decode time with BOWIE_ERR_NOT_SUPPORTED.
 *
 * The decoder does not check the flag word. v1 ignores the
 * flags; the encoder writes zero.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <stdint.h>                   uint8_t, uint16_t, uint32_t
 *   <stddef.h>                   size_t
 *   <string.h>                   memset, memcpy
 *   "bowie/types.h"              bowie_span_t
 *   "bowie/err.h"                error codes
 *   "core/internal/endian.h"     byte order helpers
 *   "proto/message.h"            the declarations
 * ============================================================================
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "bowie/types.h"
#include "bowie/err.h"
#include "core/internal/endian.h"
#include "proto/message.h"

/*
 * ============================================================================
 * NAME HELPERS
 * ============================================================================
 */

const char *bowie_proto_msg_type_name(bowie_proto_msg_type_t t)
{
    switch (t) {
    case BOWIE_PROTO_MSG_HELLO:            return "hello";
    case BOWIE_PROTO_MSG_HELLO_ACK:        return "hello_ack";

    case BOWIE_PROTO_MSG_SESSION_OPEN:     return "session_open";
    case BOWIE_PROTO_MSG_SESSION_CLOSE:    return "session_close";

    case BOWIE_PROTO_MSG_SIGNAL_OFFER:     return "signal_offer";
    case BOWIE_PROTO_MSG_SIGNAL_ANSWER:    return "signal_answer";
    case BOWIE_PROTO_MSG_SIGNAL_CANDIDATE: return "signal_candidate";

    case BOWIE_PROTO_MSG_GRANT_VERIFY:     return "grant_verify";
    case BOWIE_PROTO_MSG_GRANT_OK:         return "grant_ok";
    case BOWIE_PROTO_MSG_GRANT_DENY:       return "grant_deny";

    case BOWIE_PROTO_MSG_DATA:             return "data";

    case BOWIE_PROTO_MSG_PING:             return "ping";
    case BOWIE_PROTO_MSG_PONG:             return "pong";
    case BOWIE_PROTO_MSG_ERROR:            return "error";

    case BOWIE_PROTO_MSG_UNKNOWN:
    default:                               return "unknown";
    }
}

int bowie_proto_msg_type_is_valid(bowie_proto_msg_type_t t)
{
    switch (t) {
    case BOWIE_PROTO_MSG_HELLO:
    case BOWIE_PROTO_MSG_HELLO_ACK:

    case BOWIE_PROTO_MSG_SESSION_OPEN:
    case BOWIE_PROTO_MSG_SESSION_CLOSE:

    case BOWIE_PROTO_MSG_SIGNAL_OFFER:
    case BOWIE_PROTO_MSG_SIGNAL_ANSWER:
    case BOWIE_PROTO_MSG_SIGNAL_CANDIDATE:

    case BOWIE_PROTO_MSG_GRANT_VERIFY:
    case BOWIE_PROTO_MSG_GRANT_OK:
    case BOWIE_PROTO_MSG_GRANT_DENY:

    case BOWIE_PROTO_MSG_DATA:

    case BOWIE_PROTO_MSG_PING:
    case BOWIE_PROTO_MSG_PONG:
    case BOWIE_PROTO_MSG_ERROR:
        return 1;

    case BOWIE_PROTO_MSG_UNKNOWN:
    default:
        return 0;
    }
}

/*
 * ============================================================================
 * HEADER ENCODE
 * ============================================================================
 */

bowie_error_t bowie_proto_header_encode(
    const bowie_proto_header_t *hdr,
    uint8_t                    *buf,
    size_t                      cap)
{
    if (hdr == NULL || buf == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }
    if (cap < BOWIE_PROTO_HEADER_LEN) {
        return BOWIE_ERR_TOO_SMALL;
    }
    if (hdr->length > BOWIE_PROTO_MAX_PAYLOAD) {
        return BOWIE_ERR_TOO_LARGE;
    }

    /*
     * The header is 12 bytes:
     *
     *   offset  size  field
     *        0     1  version
     *        1     1  type
     *        2     2  flags
     *        4     4  length
     *        8     4  msg_id
     *
     * Every multi-byte field is big-endian.
     */
    buf[0] = hdr->version;
    buf[1] = hdr->type;

    bowie_be16_put(buf + 2, hdr->flags);
    bowie_be32_put(buf + 4, hdr->length);
    bowie_be32_put(buf + 8, hdr->msg_id);

    return BOWIE_OK;
}

/*
 * ============================================================================
 * HEADER DECODE
 * ============================================================================
 */

bowie_error_t bowie_proto_header_decode(
    const uint8_t         *buf,
    size_t                 len,
    bowie_proto_header_t  *hdr)
{
    if (buf == NULL || hdr == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }
    if (len < BOWIE_PROTO_HEADER_LEN) {
        return BOWIE_ERR_TOO_SMALL;
    }

    memset(hdr, 0, sizeof(*hdr));

    hdr->version = buf[0];
    hdr->type    = buf[1];

    if (hdr->version != BOWIE_PROTO_VERSION) {
        return BOWIE_ERR_NOT_SUPPORTED;
    }

    hdr->flags   = bowie_be16_get(buf + 2);
    hdr->length  = bowie_be32_get(buf + 4);
    hdr->msg_id  = bowie_be32_get(buf + 8);

    if (hdr->length > BOWIE_PROTO_MAX_PAYLOAD) {
        return BOWIE_ERR_TOO_LARGE;
    }

    return BOWIE_OK;
}

/*
 * ============================================================================
 * MESSAGE ENCODE
 * ============================================================================
 */

bowie_error_t bowie_proto_msg_encode(
    const bowie_proto_msg_t *msg,
    uint8_t                 *buf,
    size_t                   cap,
    size_t                  *out_len)
{
    if (msg == NULL || buf == NULL || out_len == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }
    if (msg->payload.len > 0u && msg->payload.data == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }
    if (msg->payload.len > BOWIE_PROTO_MAX_PAYLOAD) {
        return BOWIE_ERR_TOO_LARGE;
    }

    /*
     * The total size of the encoded message: header + payload.
     */
    size_t total = (size_t)BOWIE_PROTO_HEADER_LEN + msg->payload.len;
    if (total > cap) {
        return BOWIE_ERR_TOO_SMALL;
    }

    /*
     * The length field is set from the payload length. The
     * caller does not have to set it.
     */
    bowie_proto_header_t hdr = msg->header;
    hdr.length = (uint32_t)msg->payload.len;

    bowie_error_t rc = bowie_proto_header_encode(&hdr, buf, cap);
    if (rc != BOWIE_OK) {
        return rc;
    }

    if (msg->payload.len > 0u) {
        memcpy(buf + BOWIE_PROTO_HEADER_LEN,
               msg->payload.data,
               msg->payload.len);
    }

    *out_len = total;
    return BOWIE_OK;
}

/*
 * ============================================================================
 * MESSAGE DECODE
 * ============================================================================
 */

bowie_error_t bowie_proto_msg_decode(
    const uint8_t     *buf,
    size_t             len,
    bowie_proto_msg_t *msg)
{
    if (buf == NULL || msg == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }
    if (len < BOWIE_PROTO_HEADER_LEN) {
        return BOWIE_ERR_TOO_SMALL;
    }

    memset(msg, 0, sizeof(*msg));

    bowie_error_t rc = bowie_proto_header_decode(
        buf, len, &msg->header);
    if (rc != BOWIE_OK) {
        return rc;
    }

    /*
     * The declared payload length must fit in the buffer.
     */
    size_t need = (size_t)BOWIE_PROTO_HEADER_LEN +
                  (size_t)msg->header.length;
    if (need > len) {
        return BOWIE_ERR_TOO_SMALL;
    }

    /*
     * The payload is a borrowed span into the input buffer.
     * The caller must keep the buffer alive.
     */
    msg->payload.data = buf + BOWIE_PROTO_HEADER_LEN;
    msg->payload.len  = msg->header.length;

    return BOWIE_OK;
}

/*
 * ============================================================================
 * END OF FILE
 * ============================================================================
 */
