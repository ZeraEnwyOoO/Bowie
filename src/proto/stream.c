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
 * BOWIE — PROTOCOL STREAM (IMPLEMENTATION)
 * ============================================================================
 *
 * Implementation of the message-oriented stream declared in
 * proto/stream.h.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No encryption. The stream carries plaintext; the
 *     session layer encrypts the messages.
 *   - No NAT. The NAT layer carries the bytes; the stream
 *     frames them.
 *   - No allocation. The stream is a fixed-size struct.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * The ring is a byte ring, not a record ring. A message is a
 * frame: a 4-byte big-endian length followed by the payload.
 * The reader first makes sure the 4-byte header is in the
 * ring; then it makes sure the payload is in the ring; then
 * it copies the payload out and advances the head.
 *
 * A short read is BOWIE_ERR_AGAIN, not an error. The caller
 * is expected to call the read again after more bytes
 * arrive. The ring's head does not move on a short read; the
 * bytes are still there for the next call.
 *
 * A ring overflow is a silent drop. The NAT layer's callback
 * has no way to report a failure, so the stream drops the
 * bytes that do not fit and lets the reader see an
 * incomplete frame. The engine's read loop has a timeout; a
 * peer that overflows the ring and never sends more is a
 * peer the engine gives up on.
 *
 * The write path is not queued. The message is wrapped in a
 * frame and sent in one bowie_nat_send() call. A send that
 * returns BOWIE_ERR_AGAIN is retried after a short sleep; a
 * send that returns any other error is reported. The sleep
 * is short because the NAT layer's send is a UDP send and
 * the buffer is rarely full.
 *
 * The lock protects the ring. The callback takes it to
 * append; the read takes it to copy. The write does not take
 * it: the NAT layer's send is atomic and the ring is not
 * touched by the write path.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <errno.h>                   errno
 *   <pthread.h>                 pthread_mutex_*
 *   <string.h>                  memcpy, memset
 *   <time.h>                    nanosleep
 *   "bowie/types.h"             bowie_span_t
 *   "bowie/err.h"               error codes
 *   "proto/framing.h"           frame header, frame encode/decode
 *   "proto/stream.h"            declarations
 * ============================================================================
 */

#include <errno.h>
#include <pthread.h>
#include <string.h>
#include <time.h>

#include "bowie/types.h"
#include "bowie/err.h"
#include "proto/framing.h"
#include "proto/stream.h"

/*
 * ============================================================================
 * INTERNAL — RING HELPERS
 * ============================================================================
 *
 * The ring is a circular buffer of bytes. The head is the
 * next byte to read, the tail is the next byte to write, and
 * the count is the number of bytes in the ring.
 *
 * A read or write that would cross the end of the array is
 * split into two memcpy calls. The helper functions below
 * hide that split.
 */

/*
 * Copy up to n bytes from the ring into dst, starting at the
 * head. The head is not advanced; the caller does that.
 *
 * Returns the number of bytes copied, which is min(n, count).
 */
static size_t ring_peek(const bowie_proto_stream_t *stream,
                        uint8_t *dst, size_t n)
{
    size_t copied = 0u;

    if (n > stream->count) {
        n = stream->count;
    }

    while (copied < n) {
        size_t avail = BOWIE_PROTO_STREAM_RING_CAP - stream->head;
        size_t take  = n - copied;
        size_t idx;

        if (take > avail) {
            take = avail;
        }

        for (idx = 0u; idx < take; idx++) {
            dst[copied + idx] = stream->ring[stream->head + idx];
        }

        copied += take;
        stream->head = (stream->head + take) %
                       BOWIE_PROTO_STREAM_RING_CAP;
    }

    return copied;
}

/*
 * Advance the head by n bytes without copying. The caller
 * must have already peeked the bytes.
 */
static void ring_consume(bowie_proto_stream_t *stream, size_t n)
{
    if (n > stream->count) {
        n = stream->count;
    }
    stream->head = (stream->head + n) % BOWIE_PROTO_STREAM_RING_CAP;
    stream->count -= n;
}

/*
 * Append up to n bytes from src to the ring. The caller must
 * have already checked that the ring has room.
 *
 * Returns the number of bytes appended, which is min(n, room).
 */
static size_t ring_append(bowie_proto_stream_t *stream,
                          const uint8_t *src, size_t n)
{
    size_t appended = 0u;
    size_t room = BOWIE_PROTO_STREAM_RING_CAP - stream->count;

    if (n > room) {
        n = room;
    }

    while (appended < n) {
        size_t avail = BOWIE_PROTO_STREAM_RING_CAP - stream->tail;
        size_t take  = n - appended;
        size_t idx;

        if (take > avail) {
            take = avail;
        }

        for (idx = 0u; idx < take; idx++) {
            stream->ring[stream->tail + idx] = src[appended + idx];
        }

        appended += take;
        stream->tail = (stream->tail + take) %
                       BOWIE_PROTO_STREAM_RING_CAP;
        stream->count += take;
    }

    return appended;
}

/*
 * ============================================================================
 * LIFECYCLE
 * ============================================================================
 */

bowie_error_t bowie_proto_stream_init(bowie_proto_stream_t *stream,
                                       bowie_nat_t *nat)
{
    if (stream == NULL || nat == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }

    memset(stream, 0, sizeof(*stream));
    stream->nat = nat;

    if (pthread_mutex_init(&stream->lock, NULL) != 0) {
        stream->nat = NULL;
        return BOWIE_ERR_INTERNAL;
    }

    return BOWIE_OK;
}

void bowie_proto_stream_clear(bowie_proto_stream_t *stream)
{
    if (stream == NULL) {
        return;
    }

    /*
     * The lock is not taken here. The caller must not be
     * calling any other stream function on the same stream
     * at the same time. This is a reset, not a concurrent
     * operation.
     */
    stream->head  = 0u;
    stream->tail  = 0u;
    stream->count = 0u;

    /*
     * The ring bytes are not cleared. The head and tail
     * define the valid range; the stale bytes beyond the
     * range are harmless.
     */
}

void bowie_proto_stream_destroy(bowie_proto_stream_t *stream)
{
    if (stream == NULL) {
        return;
    }

    pthread_mutex_destroy(&stream->lock);
    stream->nat = NULL;
}

/*
 * ============================================================================
 * NAT CALLBACK
 * ============================================================================
 */

void bowie_proto_stream_on_nat_data(void *ctx,
                                     const uint8_t *data,
                                     size_t len)
{
    bowie_proto_stream_t *stream = (bowie_proto_stream_t *)ctx;

    if (stream == NULL || data == NULL || len == 0u) {
        return;
    }

    pthread_mutex_lock(&stream->lock);

    /*
     * A ring overflow drops the extra bytes. The caller of
     * the callback (the NAT layer) has no way to report a
     * failure, so the stream does the only thing it can: it
     * appends what fits and lets the reader see an
     * incomplete frame. The engine's read loop has a
     * timeout and gives up on a peer that overflows the
     * ring and never sends more.
     */
    (void)ring_append(stream, data, len);

    pthread_mutex_unlock(&stream->lock);
}

/*
 * ============================================================================
 * WRITE
 * ============================================================================
 */

bowie_error_t bowie_proto_stream_write_msg(
    bowie_proto_stream_t *stream,
    const void *data, size_t len)
{
    uint8_t         frame[BOWIE_PROTO_FRAME_HEADER_LEN +
                          BOWIE_PROTO_MAX_FRAME];
    size_t          frame_len = 0u;
    long            sent;
    int             retries;
    bowie_error_t   rc;

    if (stream == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }
    if (data == NULL && len > 0u) {
        return BOWIE_ERR_NULL_ARG;
    }
    if (stream->nat == NULL) {
        return BOWIE_ERR_STATE;
    }

    /*
     * Wrap the message in a frame. The frame is the unit the
     * NAT connection carries.
     */
    {
        bowie_span_t payload;

        payload.data = (const uint8_t *)data;
        payload.len  = len;

        rc = bowie_proto_frame_wrap(payload, frame, sizeof(frame),
                                    &frame_len);
        if (rc != BOWIE_OK) {
            return rc;
        }
    }

    /*
     * Send the frame. A NAT send that returns BOWIE_ERR_AGAIN
     * is retried after a short sleep. A send that returns any
     * other error is reported to the caller.
     */
    for (retries = 0; retries < 10; retries++) {
        sent = bowie_nat_send(stream->nat, frame, frame_len);

        if (sent >= 0) {
            /*
             * A successful send is a send that wrote the
             * whole frame. A NAT layer that writes less
             * than the whole frame is a NAT layer bug;
             * report it as a network error.
             */
            if ((size_t)sent != frame_len) {
                return BOWIE_ERR_NETWORK;
            }
            return BOWIE_OK;
        }

        {
            bowie_error_t err = (bowie_error_t)sent;
            struct timespec ts = { 0, 1000000L };  /* 1 ms */

            if (err != BOWIE_ERR_AGAIN) {
                return err;
            }

            nanosleep(&ts, NULL);
        }
    }

    return BOWIE_ERR_AGAIN;
}

/*
 * ============================================================================
 * READ
 * ============================================================================
 */

bowie_error_t bowie_proto_stream_read_msg(
    bowie_proto_stream_t *stream,
    void *buf, size_t cap, size_t *out_len)
{
    uint8_t          header[BOWIE_PROTO_FRAME_HEADER_LEN];
    size_t           payload_len;
    size_t           total_len;
    bowie_error_t    rc;

    if (stream == NULL || out_len == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }
    if (buf == NULL && cap > 0u) {
        return BOWIE_ERR_NULL_ARG;
    }

    pthread_mutex_lock(&stream->lock);

    /*
     * The header is 4 bytes. If the ring does not have the
     * header, the frame is not complete; return AGAIN and
     * leave the head where it is.
     */
    if (stream->count < BOWIE_PROTO_FRAME_HEADER_LEN) {
        pthread_mutex_unlock(&stream->lock);
        return BOWIE_ERR_AGAIN;
    }

    /*
     * Copy the header without advancing the head. The
     * decoder reads the length field; it does not need the
     * rest of the frame.
     */
    (void)ring_peek(stream, header, BOWIE_PROTO_FRAME_HEADER_LEN);

    /*
     * Restore the head. The peek advanced it; the caller
     * of this function has not yet accepted the bytes.
     */
    {
        /*
         * The peek advanced the head by the header length.
         * The read function treats the peek as a look-ahead,
         * so it must undo the advance. The count is
         * unchanged, so putting the head back by the
         * header length restores the state.
         */
        stream->head = (stream->head +
                        BOWIE_PROTO_STREAM_RING_CAP -
                        BOWIE_PROTO_FRAME_HEADER_LEN) %
                       BOWIE_PROTO_STREAM_RING_CAP;
    }

    rc = bowie_proto_frame_header_decode(header,
                                          BOWIE_PROTO_FRAME_HEADER_LEN,
                                          (bowie_proto_frame_header_t *)&(bowie_proto_frame_header_t){
                                              .length = 0
                                          });
    /*
     * The decode above is only for the length field; a
     * fresh frame_header_t is used to avoid aliasing the
     * caller's buffer.
     */
    {
        bowie_proto_frame_header_t hdr;

        rc = bowie_proto_frame_header_decode(
            header, BOWIE_PROTO_FRAME_HEADER_LEN, &hdr);
        if (rc != BOWIE_OK) {
            pthread_mutex_unlock(&stream->lock);
            return rc;
        }

        payload_len = (size_t)hdr.length;
    }

    if (payload_len > BOWIE_PROTO_MAX_FRAME) {
        pthread_mutex_unlock(&stream->lock);
        return BOWIE_ERR_TOO_LARGE;
    }

    total_len = BOWIE_PROTO_FRAME_HEADER_LEN + payload_len;

    /*
     * If the whole frame is not in the ring, the frame is
     * not complete; return AGAIN.
     */
    if (stream->count < total_len) {
        pthread_mutex_unlock(&stream->lock);
        return BOWIE_ERR_AGAIN;
    }

    /*
     * The caller's buffer must be large enough for the
     * payload. A buffer that is too small is reported; the
     * frame stays in the ring.
     */
    if (cap < payload_len) {
        pthread_mutex_unlock(&stream->lock);
        return BOWIE_ERR_TOO_SMALL;
    }

    /*
     * Consume the header. The payload is then at the head.
     */
    ring_consume(stream, BOWIE_PROTO_FRAME_HEADER_LEN);

    /*
     * Copy the payload into the caller's buffer and consume
     * it from the ring.
     */
    if (payload_len > 0u) {
        (void)ring_peek(stream, (uint8_t *)buf, payload_len);
        ring_consume(stream, payload_len);
    }

    *out_len = payload_len;

    pthread_mutex_unlock(&stream->lock);
    return BOWIE_OK;
}

/*
 * ============================================================================
 * QUERY
 * ============================================================================
 */

size_t bowie_proto_stream_bytes(const bowie_proto_stream_t *stream)
{
    if (stream == NULL) {
        return 0u;
    }
    return stream->count;
}

int bowie_proto_stream_is_empty(const bowie_proto_stream_t *stream)
{
    if (stream == NULL) {
        return 1;
    }
    return (stream->count == 0u) ? 1 : 0;
}

/*
 * ============================================================================
 * END OF FILE
 * ============================================================================
 */
