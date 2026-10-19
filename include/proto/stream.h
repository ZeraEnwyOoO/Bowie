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
 * BOWIE — PROTOCOL STREAM
 * ============================================================================
 *
 * A message-oriented stream over a byte-oriented transport.
 *
 * The NAT connection is a byte stream: it carries bytes, not
 * messages. The protocol is message-oriented: a handshake
 * message, an X25519 public key, a session control message.
 * The stream layer is what bridges the two.
 *
 * A stream wraps a NAT connection and a receive queue. The
 * caller writes messages with bowie_proto_stream_write_msg()
 * and reads messages with bowie_proto_stream_read_msg(). The
 * stream takes care of framing: it wraps each message in a
 * frame (proto/framing.h) and unwraps the frames that arrive.
 *
 * The receive queue is a fixed-size ring of byte chunks. The
 * NAT layer's recv callback appends to the ring; the read
 * function takes a message from the ring. The ring is
 * bounded; a peer that sends more than the ring can hold is
 * a peer that is not reading, and the stream reports
 * BOWIE_ERR_TOO_SMALL rather than growing without bound.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No encryption. The stream is a transport; the session
 *     layer encrypts the messages, not the stream.
 *   - No NAT. The NAT layer carries the bytes; the stream
 *     frames them.
 *   - No retransmission. The NAT connection is reliable; a
 *     byte that arrives is a byte that was sent.
 *   - No allocation. The stream is a fixed-size struct; the
 *     caller supplies it.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * The stream is a value type. It does not allocate; the
 * caller allocates the struct and the receive ring. The
 * stream's state is a pair of indices into the ring and a
 * count of bytes in flight.
 *
 * The ring is a simple array of bytes with a head and a
 * tail, like the event queue. The difference is that the
 * ring is a byte ring, not a record ring: messages have
 * variable length, so the reader has to look at the frame
 * header first, then copy the body.
 *
 * A read that does not have a complete frame in the ring
 * returns BOWIE_ERR_AGAIN. The caller is expected to call
 * the read again after more bytes arrive. This is the same
 * convention the NAT layer uses for a non-blocking recv.
 *
 * A write that does not fit the ring is not a stream
 * concern: writes go to the NAT layer directly, and the NAT
 * layer's send is either successful or not. A write that
 * fails is reported to the caller; the stream does not
 * queue outgoing messages.
 *
 * The stream's read and write are called from the same
 * thread that owns the session. The NAT layer's recv
 * callback runs on the NAT thread; it calls
 * bowie_proto_stream_on_nat_data(), which takes the
 * stream's lock and appends to the ring. The read path
 * takes the same lock.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <stdint.h>              uint8_t
 *   <stddef.h>              size_t
 *   <pthread.h>             pthread_mutex_t
 *   "bowie/types.h"         bowie_span_t
 *   "bowie/err.h"           bowie_error_t
 *   "proto/framing.h"       frame header, frame max
 *   "nat/nat.h"             bowie_nat_t
 * ============================================================================
 */

#ifndef BOWIE_PROTO_STREAM_H
#define BOWIE_PROTO_STREAM_H

#include <stdint.h>
#include <stddef.h>
#include <pthread.h>

#include "bowie/types.h"
#include "bowie/err.h"
#include "proto/framing.h"
#include "nat/nat.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ============================================================================
 * CONSTANTS
 * ============================================================================
 *
 * The receive ring capacity, in bytes. The ring holds at
 * least one maximum-size frame; a peer that sends more than
 * the ring can hold is a peer that is not reading.
 *
 * 4 KB is enough for a burst of two maximum frames and a
 * little more. A future version can make this a parameter of
 * bowie_proto_stream_init().
 */

#define BOWIE_PROTO_STREAM_RING_CAP 4096u

/*
 * ============================================================================
 * STREAM
 * ============================================================================
 *
 * The stream state. The struct is a value type; the caller
 * allocates it and initializes it with
 * bowie_proto_stream_init().
 *
 * The NAT handle is borrowed. The stream does not own it and
 * does not free it. The caller must keep the NAT handle
 * alive for the lifetime of the stream.
 *
 * The lock protects the ring. The write path does not take
 * the lock; the read path does, and so does the NAT
 * callback that appends to the ring.
 */

typedef struct bowie_proto_stream {
    bowie_nat_t    *nat;        /* borrowed */
    pthread_mutex_t lock;

    uint8_t         ring[BOWIE_PROTO_STREAM_RING_CAP];
    size_t          head;       /* next byte to read */
    size_t          tail;       /* next byte to write */
    size_t          count;      /* bytes in the ring */
} bowie_proto_stream_t;

/*
 * ============================================================================
 * LIFECYCLE
 * ============================================================================
 */

/*
 * Initialize a stream over a NAT connection.
 *
 * The NAT handle is borrowed. The caller must keep it alive
 * for the lifetime of the stream. The stream does not take
 * ownership of it.
 *
 * The function initializes the lock and resets the ring.
 * The caller is expected to install
 * bowie_proto_stream_on_nat_data() as the NAT layer's recv
 * callback before the first message arrives.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NULL_ARG if stream or nat is NULL.
 * Returns BOWIE_ERR_INTERNAL if the lock cannot be
 *   initialized.
 */
bowie_error_t bowie_proto_stream_init(bowie_proto_stream_t *stream,
                                       bowie_nat_t *nat);

/*
 * Reset a stream to the empty state.
 *
 * The ring is cleared, the lock is preserved, and the NAT
 * handle is kept. A stream that has been reset is ready for
 * a new connection.
 *
 * Passing NULL is a no-op.
 */
void bowie_proto_stream_clear(bowie_proto_stream_t *stream);

/*
 * Destroy a stream.
 *
 * The lock is destroyed. The NAT handle is not freed; the
 * stream does not own it. The caller must ensure that the
 * NAT layer no longer calls the stream's callback before
 * calling this function.
 *
 * Passing NULL is a no-op.
 */
void bowie_proto_stream_destroy(bowie_proto_stream_t *stream);

/*
 * ============================================================================
 * NAT CALLBACK
 * ============================================================================
 *
 * The function the caller installs as the NAT layer's recv
 * callback. The NAT layer calls it on its own thread for
 * each received chunk of bytes. The function appends the
 * bytes to the stream's ring.
 *
 * The bytes are copied into the ring. The NAT layer's buffer
 * is valid only for the duration of the call; the stream
 * copies what it needs.
 *
 * If the ring does not have room for the chunk, the bytes
 * are dropped and the function returns without appending.
 * The read path will see a missing frame; the peer is
 * expected to retry.
 *
 * The userdata pointer is the stream. The caller installs
 * the callback with:
 *
 *     bowie_nat_set_recv(nat, bowie_proto_stream_on_nat_data,
 *                        &stream);
 *
 * The function is declared here so the caller can take its
 * address; the implementation is in stream.c.
 */
void bowie_proto_stream_on_nat_data(void *ctx,
                                     const uint8_t *data,
                                     size_t len);

/*
 * ============================================================================
 * WRITE
 * ============================================================================
 */

/*
 * Write a message as a single frame.
 *
 * The message is wrapped in a frame (proto/framing.h) and
 * sent over the NAT connection. The NAT layer's send is
 * called exactly once; the message is not split across
 * multiple sends.
 *
 * The function blocks until the NAT layer reports success or
 * failure. A NAT send that returns BOWIE_ERR_AGAIN is
 * retried after a short sleep; a NAT send that returns any
 * other error is reported to the caller.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NULL_ARG if stream is NULL, or if data
 *   is NULL with a non-zero length.
 * Returns BOWIE_ERR_TOO_LARGE if the message does not fit a
 *   frame.
 * Returns BOWIE_ERR_STATE if the stream is not initialized.
 * Returns BOWIE_ERR_NETWORK if the NAT layer reports a
 *   failure.
 */
bowie_error_t bowie_proto_stream_write_msg(
    bowie_proto_stream_t *stream,
    const void *data, size_t len);

/*
 * ============================================================================
 * READ
 * ============================================================================
 */

/*
 * Read a message from the stream.
 *
 * The function looks at the frame header at the head of the
 * ring. If the header is not complete, or the frame body is
 * not complete, the function returns BOWIE_ERR_AGAIN; the
 * caller is expected to call the read again after more bytes
 * arrive.
 *
 * If a complete frame is in the ring, the function copies
 * the message into the caller's buffer. The buffer must be
 * at least the message length; a buffer that is too small is
 * BOWIE_ERR_TOO_SMALL and the frame is left in the ring.
 *
 * Returns BOWIE_OK on success. The message length is written
 * through out_len.
 * Returns BOWIE_ERR_NULL_ARG if stream or out_len is NULL,
 *   or if buf is NULL with a non-zero cap.
 * Returns BOWIE_ERR_AGAIN if no complete frame is in the
 *   ring.
 * Returns BOWIE_ERR_TOO_SMALL if the caller's buffer is too
 *   small for the message.
 * Returns BOWIE_ERR_FORMAT if the frame header is invalid.
 */
bowie_error_t bowie_proto_stream_read_msg(
    bowie_proto_stream_t *stream,
    void *buf, size_t cap, size_t *out_len);

/*
 * ============================================================================
 * QUERY
 * ============================================================================
 */

/*
 * Return the number of bytes currently in the ring.
 *
 * Passing NULL returns 0.
 */
size_t bowie_proto_stream_bytes(const bowie_proto_stream_t *stream);

/*
 * True when the stream has no bytes in the ring.
 *
 * Passing NULL returns 1.
 */
int bowie_proto_stream_is_empty(const bowie_proto_stream_t *stream);

/*
 * ============================================================================
 * END OF PROTOCOL STREAM
 * ============================================================================
 */

#ifdef __cplusplus
}
#endif

#endif /* BOWIE_PROTO_STREAM_H */
