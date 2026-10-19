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
 * BOWIE — ENGINE INTERNAL STATE
 * ============================================================================
 *
 * The private layout of struct bowie_engine.
 *
 * This header is internal to the Bowie library. It is not part
 * of the public API and is not installed. Only source files in the
 * src/engine directory include it.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No public API. The public header is include/engine/engine.h.
 *   - No functions. This file declares the struct only.
 *   - No subsystem state. The DHT, NAT, tunnel, gateway, and
 *     security state live in their own structs, pointed to
 *     from here. This file only ties them together.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * The struct is the engine's whole mutable state. A lock
 * protects it: every public function takes the lock before
 * touching the state, and the internal threads take the lock
 * when they report an event.
 *
 * The DHT struct is large (its arenas are inside it). It is
 * heap-allocated; a bowie_dht_t on the stack would overflow
 * the stack on any thread with a modest stack. The DHT
 * storage arrays are separate heap allocations because the
 * DHT init function wants them from the caller.
 *
 * The tunnel is borrowed. The engine never opens or closes
 * it; the caller owns it. A NULL tunnel is allowed for a
 * device that does not forward (a pure client). In that case
 * the gateway is not created.
 *
 * The session and the peer describe the current connection.
 * At most one is active at a time; the engine is a
 * point-to-point tool, not a hub. A hub is a future feature
 * and would need a list.
 *
 * The signal socket is the UDP socket the engine uses for
 * NAT signaling. It is separate from the DHT socket. The
 * signal thread reads it, decodes the message, and dispatches
 * to the NAT layer or to the connection setup.
 *
 * The nat_connected field is the result of the NAT
 * connection: 0 means pending, 1 means connected, -1 means
 * failed. The signal thread sets it; the connect and accept
 * loops read it under the lock.
 *
 * The own_* fields are the engine's identity. They are set
 * once, in bowie_engine_new(), and never change.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <pthread.h>                  pthread_mutex_t,
 *                                pthread_cond_t, pthread_t
 *   <sys/socket.h>               struct sockaddr
 *   <netinet/in.h>               struct sockaddr_in
 *   "bowie/types.h"              bowie_engine_t, bowie_peer_id_t,
 *                                bowie_public_id_t, bowie_tun_t
 *   "bowie/err.h"                bowie_error_t
 *   "engine/engine.h"            bowie_engine_config_t,
 *                                bowie_engine_state_t
 *   "dht/dht.h"                  bowie_dht_t,
 *                                bowie_dht_hash_entry_t,
 *                                bowie_dht_peer_entry_t,
 *                                bowie_dht_peer_metadata_t,
 *                                bowie_dht_rate_limit_t
 *   "nat/nat.h"                  bowie_nat_t
 *   "gateway/gateway.h"          bowie_gateway_t
 *   "security/sign.h"            bowie_sign_private_t,
 *                                bowie_sign_public_t
 *   "security/session.h"         bowie_session_t
 *   "security/revoke.h"          bowie_revoke_list_t
 *   "security/quota.h"           bowie_quota_t
 *   "net/peer.h"                 bowie_peer_t
 * ============================================================================
 */

#ifndef BOWIE_ENGINE_INTERNAL_ENGINE_H
#define BOWIE_ENGINE_INTERNAL_ENGINE_H

#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "bowie/types.h"
#include "bowie/err.h"
#include "engine/engine.h"
#include "dht/dht.h"
#include "nat/nat.h"
#include "tunnel/tun_linux.h"
#include "gateway/gateway.h"
#include "security/sign.h"
#include "security/grant.h"
#include "security/session.h"
#include "security/revoke.h"
#include "security/quota.h"
#include "net/peer.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ============================================================================
 * INTERNAL CONSTANTS
 * ============================================================================
 */

/*
 * The DHT routing table holds at most K * MAX_BUCKETS nodes.
 * The storage arrays are sized for a small box. A caller that
 * needs more calls the DHT layer directly; the engine's
 * defaults match the DHT config defaults.
 */
#define BOWIE_ENGINE_DHT_HASHES_CAP       256u
#define BOWIE_ENGINE_DHT_PEERS_CAP       4096u
#define BOWIE_ENGINE_DHT_RATE_LIMIT_CAP    64u

/*
 * The signaling socket buffer. A signaling payload is an SDP
 * blob; it is bounded by the protocol's max payload. The
 * socket receives a framed message, so the buffer is a
 * little larger than the frame's max size.
 */
#define BOWIE_ENGINE_SIGNAL_BUF_MAX \
    (BOWIE_PROTO_FRAME_HEADER_LEN + BOWIE_PROTO_MAX_PAYLOAD)

/*
 * The signaling thread poll timeout, in milliseconds. The
 * thread wakes up on this interval to check the stop flag.
 */
#define BOWIE_ENGINE_SIGNAL_POLL_MS 200u

/*
 * The default DHT search timeout, in milliseconds, when the
 * caller passes zero to bowie_engine_search_peer().
 */
#define BOWIE_ENGINE_SEARCH_DEFAULT_TIMEOUT_MS 15000u

/*
 * The default connect timeout, in milliseconds, when the
 * caller passes zero to bowie_engine_connect() or
 * bowie_engine_accept().
 */
#define BOWIE_ENGINE_CONNECT_DEFAULT_TIMEOUT_MS 30000u

/*
 * ============================================================================
 * ENGINE STRUCT
 * ============================================================================
 */

/* Forward Declaration */
struct bowie_engine_event_queue;
struct bowie_engine {
    /*
     * ----------------------------------------------------------------
     * Synchronization
     * ----------------------------------------------------------------
     *
     * The lock protects every mutable field below. It is
     * recursive only in the sense that an internal thread
     * does not take it while the caller holds it; the
     * internal threads only wake up and take it themselves.
     *
     * nat_cond is broadcast when the NAT connection reaches
     * a terminal state. The connect and accept loops wait on
     * it with the lock held.
     */
    pthread_mutex_t     lock;
    pthread_cond_t      nat_cond;

    /*
     * ----------------------------------------------------------------
     * State and configuration
     * ----------------------------------------------------------------
     *
     * The state is the engine's lifecycle state. The config
     * is a copy of what the caller passed to
     * bowie_engine_new(); its string fields are borrowed
     * from the caller.
     */
    bowie_engine_state_t state;
    bowie_engine_config_t cfg;

    /*
     * ----------------------------------------------------------------
     * Identity
     * ----------------------------------------------------------------
     *
     * The Ed25519 keypair is generated once, in
     * bowie_engine_new(), and never changes. The public ID
     * is the raw public key. The peer ID is derived from the
     * public ID with the hash function in use. The DHT node
     * ID is a separate 20-byte value; it is derived from the
     * public ID as well, but it is kept separate because the
     * two identifiers serve different layers.
     */
    bowie_sign_private_t own_sign_priv;
    bowie_sign_public_t  own_sign_pub;
    bowie_public_id_t    own_public_id;
    bowie_peer_id_t      own_peer_id;
    bowie_dht_node_id_t  own_dht_id;

    /*
     * ----------------------------------------------------------------
     * DHT
     * ----------------------------------------------------------------
     *
     * The DHT struct is heap-allocated because its arenas
     * are stored inside it and the struct is about 200 KB.
     *
     * The storage arrays are separate heap allocations. The
     * engine owns them; the DHT layer only borrows them. The
     * capacities are compile-time constants; a future version
     * can make them part of the config.
     *
     * The metadata and rate-limit arrays are allocated only
     * when the DHT config asks for them. The metadata array
     * is NULL when store_metadata is zero; the rate-limit
     * array is NULL when the security level is not STRICT.
     */
    bowie_dht_t                  *dht;
    bowie_dht_hash_entry_t       *dht_hashes;
    bowie_dht_peer_entry_t       *dht_peers;
    bowie_dht_peer_metadata_t    *dht_metadata;      /* may be NULL */
    bowie_dht_rate_limit_t       *dht_rate_limits;   /* may be NULL */
    uint16_t                      dht_port;          /* actual port */

    /*
     * ----------------------------------------------------------------
     * NAT
     * ----------------------------------------------------------------
     *
     * The NAT handle is heap-allocated by bowie_nat_new(). It
     * is created in bowie_engine_start() and freed in
     * bowie_engine_stop().
     *
     * nat_connected carries the result of the most recent
     * NAT connect: 0 while pending, 1 on success, -1 on
     * failure. The signal thread sets it; the connect and
     * accept loops wait on nat_cond for it to be non-zero.
     */
    bowie_nat_t *nat;
    int          nat_connected;

    /*
     * ----------------------------------------------------------------
     * Tunnel (borrowed)
     * ----------------------------------------------------------------
     *
     * The tunnel is supplied by the caller at start time. The
     * engine never closes it. A NULL tunnel is allowed for a
     * pure client; in that case the gateway is not created.
     */
    bowie_tun_t *tun;

    /*
     * ----------------------------------------------------------------
     * Gateway
     * ----------------------------------------------------------------
     *
     * The gateway is created when a connection reaches
     * RUNNING and the engine has a tunnel and a session. It
     * is stopped and freed on disconnect and on stop.
     */
    bowie_gateway_t *gateway;

    /*
     * ----------------------------------------------------------------
     * Security
     * ----------------------------------------------------------------
     *
     * The revocation list and the quota belong to the
     * engine; the security layer reads them. The list is a
     * value type stored inline. The quota is a value type
     * stored inline.
     */
    bowie_revoke_list_t revoke_list;
    bowie_quota_t       quota;

    bowie_engine_event_queue_t events; 
    /*
     * ----------------------------------------------------------------
     * Current connection
     * ----------------------------------------------------------------
     *
     * At most one connection is active at a time. The peer
     * describes the remote node. The session is NULL when no
     * connection is active; it is created by the handshake
     * and freed on disconnect and on stop.
     *
     * The grant is the grant the local engine issued or
     * accepted for this connection. It is zero when the
     * engine is the owner and has not yet issued one.
     *
     * The signal_addr is the peer's signaling address. It is
     * learned from the DHT (for an outbound connection) or
     * from the first signaling message (for an inbound one).
     * It is valid only while signal_addr_valid is 1.
     */
    bowie_peer_t    peer;
    bowie_session_t *session;
    bowie_grant_t   grant;

    /*
     * ----------------------------------------------------------------
     * Signaling channel
     * ----------------------------------------------------------------
     *
     * The signaling socket is a UDP socket separate from the
     * DHT socket. The engine uses it to exchange NAT
     * signaling payloads (SDP blobs) with the peer. The
     * thread reads the socket and dispatches each message to
     * the NAT layer or to the connection setup.
     *
     * The socket is open only while the engine is not
     * STOPPED. The thread is started in bowie_engine_start()
     * and joined in bowie_engine_stop().
     */
    int              signal_fd;
    uint16_t         signal_port;            /* actual port */
    pthread_t        signal_thread;
    int              signal_running;         /* read by the thread */
    int              signal_stop;            /* set to 1 to stop */

    struct sockaddr_in peer_signal_addr;     /* peer's signaling address */
    int                peer_signal_addr_valid;

    /*
     * ----------------------------------------------------------------
     * Outbound connection request
     * ----------------------------------------------------------------
     *
     * When the caller calls bowie_engine_connect(), the
     * engine searches the peer, then asks the NAT layer to
     * connect. The NAT layer produces signaling payloads
     * through the signal_send callback; the engine sends
     * them to the peer over the signaling socket.
     *
     * The pending_offer flag is set when the engine is
     * waiting for the peer's signaling response. It is
     * cleared when the response arrives or the connect
     * times out.
     */
    int pending_offer;

    /*
     * ----------------------------------------------------------------
     * Inbound connection request
     * ----------------------------------------------------------------
     *
     * When a peer sends the first signaling message, the
     * engine creates a NAT instance and asks it to accept
     * the peer. The inbound_peer_id is the peer's ID, as
     * carried in the signaling message's handshake. The
     * inbound_offer flag is set while the engine is waiting
     * for the local NAT layer to gather candidates.
     */
    int                 inbound_offer;
    bowie_peer_id_t     inbound_peer_id;
};

/*
 * ============================================================================
 * END OF ENGINE INTERNAL STATE
 * ============================================================================
 */

#ifdef __cplusplus
}
#endif

#endif /* BOWIE_ENGINE_INTERNAL_ENGINE_H */
