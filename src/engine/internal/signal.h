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
 * BOWIE — ENGINE SIGNALING CHANNEL (INTERNAL)
 * ============================================================================
 *
 * The UDP signaling channel between two engines.
 *
 * The NAT layer produces and consumes SDP blobs, but it does
 * not send them. The signaling channel is what carries them
 * between the two peers. It is a plain UDP socket with a
 * simple wire format:
 *
 *   [ 4 bytes: frame length, big-endian ]
 *   [ frame:   a proto message (see proto/message.h) ]
 *
 * The signaling channel is NOT encrypted. The handshake runs
 * over the NAT connection, after the signaling channel has
 * done its job. The signaling channel only carries SDP
 * blobs, which are not secret: an SDP blob reveals the
 * peer's candidate addresses, nothing more.
 *
 * The channel is a per-engine resource. It is opened in
 * bowie_engine_start() and closed in bowie_engine_stop().
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No NAT. The channel carries SDP blobs; it does not
 *     produce or parse them.
 *   - No session. The channel is unencrypted by design; see
 *     the design notes.
 *   - No retransmission. UDP is best-effort; a lost
 *     signaling payload is recovered by the caller's retry.
 *   - No authentication. The channel accepts a message from
 *     any address. The handshake that follows is what
 *     authenticates the peer.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * The signaling socket is separate from the DHT socket. The
 * two have different purposes and different concurrency
 * models: the DHT socket is owned by the DHT thread; the
 * signaling socket is owned by the signaling thread. Keeping
 * them apart avoids a lock on the DHT thread's hot path.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <stdint.h>              uint16_t
 *   <stddef.h>              size_t
 *   "bowie/types.h"         bowie_addr_t, bowie_peer_id_t,
 *                           bowie_span_t
 *   "bowie/err.h"           bowie_error_t
 *   "engine/internal/engine.h"  struct bowie_engine
 * ============================================================================
 */

#ifndef BOWIE_ENGINE_INTERNAL_SIGNAL_H
#define BOWIE_ENGINE_INTERNAL_SIGNAL_H

#include <stdint.h>
#include <stddef.h>

#include "bowie/types.h"
#include "bowie/err.h"
#include "engine/internal/engine.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ============================================================================
 * LIFECYCLE
 * ============================================================================
 */

/*
 * Open the signaling socket and start the signaling thread.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NULL_ARG if e is NULL.
 * Returns BOWIE_ERR_NETWORK if the socket cannot be opened
 *   or bound.
 * Returns BOWIE_ERR_INTERNAL if the thread cannot be
 *   created.
 */
bowie_error_t bowie_engine_signal_open(bowie_engine_t *e,
                                       uint16_t port);

/*
 * Stop the signaling thread and close the socket.
 *
 * Passing NULL for e is a no-op.
 */
void bowie_engine_signal_close(bowie_engine_t *e);

/*
 * ============================================================================
 * SEND
 * ============================================================================
 */

/*
 * Send a signaling payload to a peer.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NULL_ARG if e or to is NULL.
 * Returns BOWIE_ERR_STATE if the signaling channel is not
 *   open.
 * Returns BOWIE_ERR_NETWORK if the send fails.
 */
bowie_error_t bowie_engine_signal_send(bowie_engine_t *e,
                                       const bowie_addr_t *to,
                                       const void *data, size_t len);

/*
 * ============================================================================
 * ADDRESS
 * ============================================================================
 */

void bowie_engine_signal_peer_addr(const bowie_engine_t *e,
                                   bowie_addr_t *out);

uint16_t bowie_engine_signal_local_port(const bowie_engine_t *e);

/*
 * ============================================================================
 * END OF SIGNAL
 * ============================================================================
 */

#ifdef __cplusplus
}
#endif

#endif /* BOWIE_ENGINE_INTERNAL_SIGNAL_H */
