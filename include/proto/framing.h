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
 * BOWIE — PROTOCOL FRAMING
 * ============================================================================
 *
 * Frame encoding and decoding for the Bowie protocol.
 *
 * A frame is the unit that the transport carries. A frame wraps
 * a message. The framing layer is the boundary between the
 * transport (which carries bytes) and the protocol (which
 * carries messages).
 *
 * A frame has a fixed-size header followed by the encoded
 * message. The frame header is smaller than the message header;
 * its only job is to say how long the message is.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No allocation.
 *   - No I/O. Nothing here touches a socket.
 *   - No encryption.
 *   - No compression.
 *   - No transport. A frame is encoded into a buffer and decoded
 *     from a buffer; the transport is a separate concern.
 *   - No message parsing. A frame carries a message; the message
 *     layer parses it. The framing layer does not look inside
 *     the message.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * The frame header is 4 bytes:
 *
 *   offset  size  field
 *   ------  ----  -----
 *        0     4  length
 *
 * The length field is the length of the message that follows,
 * in bytes. It is encoded in network byte order.
 *
 * The frame is deliberately simple. It does not carry a magic
 * number, a version, or a checksum. The message header carries
 * the version, and the transport (UDP) carries a checksum. A
 * second checksum at the framing layer would be redundant.
 *
 * A frame whose length is zero is valid: it carries an empty
 * message. The message layer decides whether an empty message
 * is meaningful.
 *
 * A frame whose length is greater than BOWIE_PROTO_MAX_FRAME
 * is rejected at encode time and at decode time. The bound is
 * chosen so that a frame fits in a single UDP datagram on every
 * platform Bowie targets.
 *
 * The framing layer is the only place that knows the size of a
 * frame on the wire. The message layer works on a message
 * buffer; the transport layer works on a byte stream. The
 * framing layer converts between the two.
 *
 * ----------------------------------------------------------------------------
 * Transport independence
 * ----------------------------------------------------------------------------
 *
 * A frame is a unit of bytes. The framing layer does not know
 * whether the transport is UDP, TCP, or a stream. On a datagram
 * transport, one frame is one datagram. On a stream transport,
 * frames are concatenated and the receiver reads the length
 * field to find the boundary.
 *
 * This file provides both:
 *
 *   - A one-shot encode and decode, for a datagram transport.
 *   - A length-prefix read, for a stream transport.
 *
 * The one-shot functions are the common case; the stream read
 * is provided so that a future stream transport does not need a
 * second framing format.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <stdint.h>                   uint8_t, uint32_t
 *   <stddef.h>                   size_t
 *   "bowie/types.h"              bowie_span_t
 *   "bowie/err.h"                error codes
 *   "proto/message.h"            the message type
 * ============================================================================
 */

#ifndef BOWIE_PROTO_FRAMING_H
#define BOWIE_PROTO_FRAMING_H

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
 * FRAME HEADER SIZE
 * ============================================================================
 *
 * The fixed size of the frame header, in bytes.
 */

#define BOWIE_PROTO_FRAME_HEADER_LEN 4u

/*
 * ============================================================================
 * MAXIMUM FRAME
 * ============================================================================
 *
 * The maximum length of the message carried by a single frame,
 * in bytes.
 *
 * The value is chosen so that a frame fits in a single UDP
 * datagram without fragmentation on every platform Bowie
 * targets.
 */

#define BOWIE_PROTO_MAX_FRAME BOWIE_PROTO_MAX_PAYLOAD

/*
 * ============================================================================
 * FRAME HEADER
 * ============================================================================
 *
 * The decoded form of a frame header. The length field is in
 * host byte order.
 */

typedef struct bowie_proto_frame_header {
    uint32_t length;   /* length of the message that follows */
} bowie_proto_frame_header_t;

/*
 * ============================================================================
 * FRAME
 * ============================================================================
 *
 * A decoded frame: a header and a borrowed message span.
 *
 * The message span points into the input buffer. The caller
 * must keep the input buffer alive for as long as it uses the
 * frame.
 */

typedef struct bowie_proto_frame {
    bowie_proto_frame_header_t header;
    bowie_span_t               message;
} bowie_proto_frame_t;

/*
 * ============================================================================
 * FRAME HEADER ENCODE / DECODE
 * ============================================================================
 */

/*
 * Encode a frame header into a caller-supplied buffer.
 *
 * The buffer must be at least BOWIE_PROTO_FRAME_HEADER_LEN
 * bytes. The length field is written in network byte order.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NULL_ARG if hdr or buf is NULL.
 * Returns BOWIE_ERR_TOO_SMALL if cap is less than
 *   BOWIE_PROTO_FRAME_HEADER_LEN.
 * Returns BOWIE_ERR_TOO_LARGE if hdr->length is greater than
 *   BOWIE_PROTO_MAX_FRAME.
 */
bowie_error_t bowie_proto_frame_header_encode(
    const bowie_proto_frame_header_t *hdr,
    uint8_t                          *buf,
    size_t                            cap);

/*
 * Decode a frame header from a caller-supplied buffer.
 *
 * The buffer must be at least BOWIE_PROTO_FRAME_HEADER_LEN
 * bytes. The length field is read from network byte order into
 * host byte order.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NULL_ARG if buf or hdr is NULL.
 * Returns BOWIE_ERR_TOO_SMALL if len is less than
 *   BOWIE_PROTO_FRAME_HEADER_LEN.
 * Returns BOWIE_ERR_TOO_LARGE if the length field is greater
 *   than BOWIE_PROTO_MAX_FRAME.
 */
bowie_error_t bowie_proto_frame_header_decode(
    const uint8_t               *buf,
    size_t                       len,
    bowie_proto_frame_header_t  *hdr);

/*
 * ============================================================================
 * FRAME ENCODE / DECODE
 * ============================================================================
 */

/*
 * Encode a frame into a caller-supplied buffer.
 *
 * The frame is a 4-byte header followed by the message bytes.
 * The message is taken from the frame's message span. The
 * frame's header is not used; the length is computed from the
 * message span.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NULL_ARG if frame or buf is NULL, or if
 *   the message span is malformed.
 * Returns BOWIE_ERR_TOO_SMALL if cap is too small.
 * Returns BOWIE_ERR_TOO_LARGE if the message is too long.
 */
bowie_error_t bowie_proto_frame_encode(
    const bowie_proto_frame_t *frame,
    uint8_t                   *buf,
    size_t                     cap,
    size_t                    *out_len);

/*
 * Decode a frame from a caller-supplied buffer.
 *
 * The frame header is decoded first. The message span points
 * into the input buffer.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NULL_ARG if buf or frame is NULL.
 * Returns BOWIE_ERR_TOO_SMALL if len is less than the frame
 *   header or less than the declared message.
 * Returns BOWIE_ERR_TOO_LARGE if the declared message is
 *   greater than BOWIE_PROTO_MAX_FRAME.
 */
bowie_error_t bowie_proto_frame_decode(
    const uint8_t       *buf,
    size_t               len,
    bowie_proto_frame_t *frame);

/*
 * ============================================================================
 * MESSAGE WRAPPER
 * ============================================================================
 *
 * A convenience pair that wraps an encoded message in a frame
 * and unwraps a frame into a message.
 *
 * The wrapper does not encode or decode the message itself. It
 * copies the encoded message bytes into or out of the frame.
 */

/*
 * Wrap an encoded message in a frame.
 *
 * The message bytes are copied. The caller may free the source
 * after the call returns.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NULL_ARG if any required pointer is NULL.
 * Returns BOWIE_ERR_TOO_SMALL if cap is too small.
 * Returns BOWIE_ERR_TOO_LARGE if the message is too long.
 */
bowie_error_t bowie_proto_frame_wrap(
    bowie_span_t  message,
    uint8_t      *buf,
    size_t        cap,
    size_t       *out_len);

/*
 * Unwrap a frame into a borrowed message span.
 *
 * The message span points into the input buffer. The caller
 * must keep the input buffer alive.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NULL_ARG if any required pointer is NULL.
 * Returns BOWIE_ERR_TOO_SMALL if len is too small.
 * Returns BOWIE_ERR_TOO_LARGE if the frame is too large.
 */
bowie_error_t bowie_proto_frame_unwrap(
    const uint8_t *buf,
    size_t         len,
    bowie_span_t  *out_message);

/*
 * ============================================================================
 * STREAM READ
 * ============================================================================
 *
 * A helper for a stream transport. Given a buffer that starts
 * with a frame header, the function returns the total number
 * of bytes the frame occupies, including the header.
 *
 * A caller that reads from a stream uses this to know how many
 * bytes to read before it has a complete frame.
 */

/*
 * Return the total size of the frame at the start of the
 * buffer, including the frame header.
 *
 * The buffer must be at least BOWIE_PROTO_FRAME_HEADER_LEN
 * bytes.
 *
 * Returns BOWIE_OK on success and writes the total size
 *   through out_total.
 * Returns BOWIE_ERR_NULL_ARG if buf or out_total is NULL.
 * Returns BOWIE_ERR_TOO_SMALL if len is less than the frame
 *   header.
 * Returns BOWIE_ERR_TOO_LARGE if the declared message is
 *   greater than BOWIE_PROTO_MAX_FRAME.
 */
bowie_error_t bowie_proto_frame_stream_size(
    const uint8_t *buf,
    size_t         len,
    size_t        *out_total);

/*
 * ============================================================================
 * END OF PROTOCOL FRAMING
 * ============================================================================
 */

#ifdef __cplusplus
}
#endif

#endif /* BOWIE_PROTO_FRAMING_H */
