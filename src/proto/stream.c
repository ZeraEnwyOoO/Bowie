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
 * INTERNAL — RING PEEK
 * ============================================================================
 *
 * Copy up to n bytes from the ring starting at the head,
 * without advancing the head and without taking the lock.
 * The caller must hold the lock.
 *
 * Returns the number of bytes copied, which is min(n, count).
 */

static size_t ring_peek_locked(const bowie_proto_stream_t *stream,
                               uint8_t *dst, size_t n)
{
    size_t copied = 0u;
    size_t head   = stream->head;

    if (n > stream->count) {
        n = stream->count;
    }

    while (copied < n) {
        size_t avail = BOWIE_PROTO_STREAM_RING_CAP - head;
        size_t take  = n - copied;
        size_t idx;

        if (take > avail) {
            take = avail;
        }

        for (idx = 0u; idx < take; idx++) {
            dst[copied + idx] = stream->ring[head + idx];
        }

        copied += take;
        head = (head + take) % BOWIE_PROTO_STREAM_RING_CAP;
    }

    return copied;
}

/*
 * ============================================================================
 * INTERNAL — RING CONSUME
 * ============================================================================
 *
 * Advance the head by n bytes without copying. The caller
 * must hold the lock.
 */

static void ring_consume_locked(bowie_proto_stream_t *stream, size_t n)
{
    if (n > stream->count) {
        n = stream->count;
    }
    stream->head = (stream->head + n) % BOWIE_PROTO_STREAM_RING_CAP;
    stream->count -= n;
}

/*
 * ============================================================================
 * INTERNAL — RING APPEND
 * ============================================================================
 *
 * Append up to n bytes from src to the ring. The caller must
 * hold the lock.
 *
 * Returns the number of bytes appended, which is min(n, room).
 */

static size_t ring_append_locked(bowie_proto_stream_t *stream,
                                 const uint8_t *src, size_t n)
{
    size_t appended = 0u;
    size_t tail     = stream->tail;
    size_t room     = BOWIE_PROTO_STREAM_RING_CAP - stream->count;

    if (n > room) {
        n = room;
    }

    while (appended < n) {
        size_t avail = BOWIE_PROTO_STREAM_RING_CAP - tail;
        size_t take  = n - appended;
        size_t idx;

        if (take > avail) {
            take = avail;
        }

        for (idx = 0u; idx < take; idx++) {
            stream->ring[tail + idx] = src[appended + idx];
        }

        appended += take;
        tail = (tail + take) % BOWIE_PROTO_STREAM_RING_CAP;
    }

    stream->tail  = tail;
    stream->count += appended;

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

    pthread_mutex_lock(&stream->lock);
    stream->head  = 0u;
    stream->tail  = 0u;
    stream->count = 0u;
    pthread_mutex_unlock(&stream->lock);
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
    (void)ring_append_locked(stream, data, len);
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

    for (retries = 0; retries < 10; retries++) {
        sent = bowie_nat_send(stream->nat, frame, frame_len);

        if (sent >= 0) {
            if ((size_t)sent != frame_len) {
                return BOWIE_ERR_NETWORK;
            }
            return BOWIE_OK;
        }

        {
            bowie_error_t err = (bowie_error_t)sent;
            struct timespec ts = { 0, 1000000L };

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
    uint8_t                 header[BOWIE_PROTO_FRAME_HEADER_LEN];
    bowie_proto_frame_header_t hdr;
    size_t                  payload_len;
    size_t                  total_len;
    bowie_error_t           rc;

    if (stream == NULL || out_len == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }
    if (buf == NULL && cap > 0u) {
        return BOWIE_ERR_NULL_ARG;
    }

    pthread_mutex_lock(&stream->lock);

    /*
     * Peek the header without advancing the head.
     */
    if (stream->count < BOWIE_PROTO_FRAME_HEADER_LEN) {
        pthread_mutex_unlock(&stream->lock);
        return BOWIE_ERR_AGAIN;
    }

    (void)ring_peek_locked(stream, header,
                           BOWIE_PROTO_FRAME_HEADER_LEN);

    rc = bowie_proto_frame_header_decode(
        header, BOWIE_PROTO_FRAME_HEADER_LEN, &hdr);
    if (rc != BOWIE_OK) {
        pthread_mutex_unlock(&stream->lock);
        return rc;
    }

    payload_len = (size_t)hdr.length;
    total_len   = BOWIE_PROTO_FRAME_HEADER_LEN + payload_len;

    /*
     * The whole frame must be in the ring.
     */
    if (stream->count < total_len) {
        pthread_mutex_unlock(&stream->lock);
        return BOWIE_ERR_AGAIN;
    }

    /*
     * The caller's buffer must be large enough.
     */
    if (cap < payload_len) {
        pthread_mutex_unlock(&stream->lock);
        return BOWIE_ERR_TOO_SMALL;
    }

    /*
     * Consume the header and copy the payload.
     */
    ring_consume_locked(stream, BOWIE_PROTO_FRAME_HEADER_LEN);

    if (payload_len > 0u) {
        (void)ring_peek_locked(stream, (uint8_t *)buf, payload_len);
        ring_consume_locked(stream, payload_len);
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
