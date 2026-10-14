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
 * BOWIE — PROTOCOL FRAMING IMPLEMENTATION
 * ============================================================================
 *
 * Frame header and frame encoding and decoding for the Bowie
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
 *   - No transport.
 *   - No message parsing.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * The frame header is 4 bytes: one big-endian uint32 length
 * field. The encoder writes the length field from the message
 * span; the decoder reads it.
 *
 * The whole-frame encoder writes the header and then copies
 * the message bytes. The whole-frame decoder reads the header
 * and then points the message span into the input buffer.
 *
 * The wrap and unwrap helpers are the common case: a caller
 * has an encoded message and wants a frame, or has a frame and
 * wants the encoded message. The wrap copies the message; the
 * unwrap borrows it.
 *
 * The stream-size helper is for a stream transport. It reads
 * the header and returns the total frame size (header plus
 * message) without copying anything.
 *
 * The byte order handling uses the helpers from
 * bowie/core/internal/endian.h.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <stdint.h>                   uint8_t, uint32_t
 *   <stddef.h>                   size_t
 *   <string.h>                   memset, memcpy
 *   "bowie/types.h"              bowie_span_t
 *   "bowie/err.h"                error codes
 *   "core/internal/endian.h"     byte order helpers
 *   "proto/framing.h"            the declarations
 * ============================================================================
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "bowie/types.h"
#include "bowie/err.h"
#include "core/internal/endian.h"
#include "proto/framing.h"

/*
 * ============================================================================
 * FRAME HEADER ENCODE
 * ============================================================================
 */

bowie_error_t bowie_proto_frame_header_encode(
    const bowie_proto_frame_header_t *hdr,
    uint8_t                          *buf,
    size_t                            cap)
{
    if (hdr == NULL || buf == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }
    if (cap < BOWIE_PROTO_FRAME_HEADER_LEN) {
        return BOWIE_ERR_TOO_SMALL;
    }
    if (hdr->length > BOWIE_PROTO_MAX_FRAME) {
        return BOWIE_ERR_TOO_LARGE;
    }

    /*
     * The frame header is 4 bytes: one big-endian uint32.
     */
    bowie_be32_put(buf, hdr->length);

    return BOWIE_OK;
}

/*
 * ============================================================================
 * FRAME HEADER DECODE
 * ============================================================================
 */

bowie_error_t bowie_proto_frame_header_decode(
    const uint8_t               *buf,
    size_t                       len,
    bowie_proto_frame_header_t  *hdr)
{
    if (buf == NULL || hdr == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }
    if (len < BOWIE_PROTO_FRAME_HEADER_LEN) {
        return BOWIE_ERR_TOO_SMALL;
    }

    memset(hdr, 0, sizeof(*hdr));

    hdr->length = bowie_be32_get(buf);

    if (hdr->length > BOWIE_PROTO_MAX_FRAME) {
        return BOWIE_ERR_TOO_LARGE;
    }

    return BOWIE_OK;
}

/*
 * ============================================================================
 * FRAME ENCODE
 * ============================================================================
 */

bowie_error_t bowie_proto_frame_encode(
    const bowie_proto_frame_t *frame,
    uint8_t                   *buf,
    size_t                     cap,
    size_t                    *out_len)
{
    if (frame == NULL || buf == NULL || out_len == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }
    if (frame->message.len > 0u && frame->message.data == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }
    if (frame->message.len > BOWIE_PROTO_MAX_FRAME) {
        return BOWIE_ERR_TOO_LARGE;
    }

    /*
     * The total size of the encoded frame: header + message.
     */
    size_t total = (size_t)BOWIE_PROTO_FRAME_HEADER_LEN +
                   frame->message.len;
    if (total > cap) {
        return BOWIE_ERR_TOO_SMALL;
    }

    /*
     * The length field is set from the message length. The
     * frame's header field is not used.
     */
    bowie_proto_frame_header_t hdr;
    hdr.length = (uint32_t)frame->message.len;

    bowie_error_t rc = bowie_proto_frame_header_encode(
        &hdr, buf, cap);
    if (rc != BOWIE_OK) {
        return rc;
    }

    if (frame->message.len > 0u) {
        memcpy(buf + BOWIE_PROTO_FRAME_HEADER_LEN,
               frame->message.data,
               frame->message.len);
    }

    *out_len = total;
    return BOWIE_OK;
}

/*
 * ============================================================================
 * FRAME DECODE
 * ============================================================================
 */

bowie_error_t bowie_proto_frame_decode(
    const uint8_t       *buf,
    size_t               len,
    bowie_proto_frame_t *frame)
{
    if (buf == NULL || frame == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }
    if (len < BOWIE_PROTO_FRAME_HEADER_LEN) {
        return BOWIE_ERR_TOO_SMALL;
    }

    memset(frame, 0, sizeof(*frame));

    bowie_error_t rc = bowie_proto_frame_header_decode(
        buf, len, &frame->header);
    if (rc != BOWIE_OK) {
        return rc;
    }

    /*
     * The declared message length must fit in the buffer.
     */
    size_t need = (size_t)BOWIE_PROTO_FRAME_HEADER_LEN +
                  (size_t)frame->header.length;
    if (need > len) {
        return BOWIE_ERR_TOO_SMALL;
    }

    /*
     * The message is a borrowed span into the input buffer.
     */
    frame->message.data = buf + BOWIE_PROTO_FRAME_HEADER_LEN;
    frame->message.len  = frame->header.length;

    return BOWIE_OK;
}

/*
 * ============================================================================
 * MESSAGE WRAPPER
 * ============================================================================
 */

bowie_error_t bowie_proto_frame_wrap(
    bowie_span_t  message,
    uint8_t      *buf,
    size_t        cap,
    size_t       *out_len)
{
    if (buf == NULL || out_len == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }
    if (message.len > 0u && message.data == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }
    if (message.len > BOWIE_PROTO_MAX_FRAME) {
        return BOWIE_ERR_TOO_LARGE;
    }

    size_t total = (size_t)BOWIE_PROTO_FRAME_HEADER_LEN + message.len;
    if (total > cap) {
        return BOWIE_ERR_TOO_SMALL;
    }

    bowie_proto_frame_header_t hdr;
    hdr.length = (uint32_t)message.len;

    bowie_error_t rc = bowie_proto_frame_header_encode(
        &hdr, buf, cap);
    if (rc != BOWIE_OK) {
        return rc;
    }

    if (message.len > 0u) {
        memcpy(buf + BOWIE_PROTO_FRAME_HEADER_LEN,
               message.data,
               message.len);
    }

    *out_len = total;
    return BOWIE_OK;
}

bowie_error_t bowie_proto_frame_unwrap(
    const uint8_t *buf,
    size_t         len,
    bowie_span_t  *out_message)
{
    if (buf == NULL || out_message == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }
    if (len < BOWIE_PROTO_FRAME_HEADER_LEN) {
        return BOWIE_ERR_TOO_SMALL;
    }

    bowie_proto_frame_header_t hdr;
    bowie_error_t rc = bowie_proto_frame_header_decode(
        buf, len, &hdr);
    if (rc != BOWIE_OK) {
        return rc;
    }

    size_t need = (size_t)BOWIE_PROTO_FRAME_HEADER_LEN +
                  (size_t)hdr.length;
    if (need > len) {
        return BOWIE_ERR_TOO_SMALL;
    }

    out_message->data = buf + BOWIE_PROTO_FRAME_HEADER_LEN;
    out_message->len  = hdr.length;

    return BOWIE_OK;
}

/*
 * ============================================================================
 * STREAM READ
 * ============================================================================
 */

bowie_error_t bowie_proto_frame_stream_size(
    const uint8_t *buf,
    size_t         len,
    size_t        *out_total)
{
    if (buf == NULL || out_total == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }
    if (len < BOWIE_PROTO_FRAME_HEADER_LEN) {
        return BOWIE_ERR_TOO_SMALL;
    }

    uint32_t msg_len = bowie_be32_get(buf);
    if (msg_len > BOWIE_PROTO_MAX_FRAME) {
        return BOWIE_ERR_TOO_LARGE;
    }

    *out_total = (size_t)BOWIE_PROTO_FRAME_HEADER_LEN +
                 (size_t)msg_len;
    return BOWIE_OK;
}

/*
 * ============================================================================
 * END OF FILE
 * ============================================================================
 */
