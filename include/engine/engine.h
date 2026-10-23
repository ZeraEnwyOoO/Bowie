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

#ifndef BOWIE_ENGINE_ENGINE_H
#define BOWIE_ENGINE_ENGINE_H

#include <stdint.h>
#include <stddef.h>

#include "bowie/types.h"
#include "bowie/err.h"
#include "bowie/hooks.h"
#include "bowie/config.h"     /* For bowie_config_t */
#include "dht/node.h"         /* For bowie_dht_node_t */
#include "dht/config.h"       /* For bootstrap endpoints */
#include "security/sign.h"    /* For bowie_sign_signature_t */
#include "security/grant.h"   /* For owner-issued access grants */
#include "gateway/gateway.h"  /* For gateway stats and source egress */

#ifdef __cplusplus
extern "C" {
#endif


/*
 * ============================================================================
 * CONFIGURATION
 * ============================================================================
 */

typedef struct bowie_engine_config {
    /* Optional durable source-grant usage store. load returns 1 when found,
     * 0 when absent, and -1 on storage error. save must be durable before
     * returning success; returning 0 blocks the packet and disconnects. */
    int (*grant_usage_load)(void *context, const bowie_grant_id_t *grant_id,
                            uint64_t limit, uint64_t *used);
    int (*grant_usage_save)(void *context, const bowie_grant_id_t *grant_id,
                            uint64_t limit, uint64_t used);
    void *grant_usage_context;
    /* Optional thread-safe platform hook called before DHT, signaling, or
     * numeric ICE endpoints are used. Return nonzero when the route is ready;
     * zero prevents that outbound operation. */
    int (*prepare_underlay_address)(void *context, int family,
                                    const uint8_t *address, size_t address_len);
    void *underlay_context;
    /* Optional local veto after PoO and peer identity verification. Return
     * non-zero to approve. NULL means the valid owner grant is sufficient.
     * The context must remain valid until the engine is freed. */
    int (*authorize_discovered_peer)(void *context,
                                     const bowie_peer_id_t *peer_id);
    void *authorize_discovered_peer_context;
    /* Explicit opt-out for trusted legacy links; zero (default) requires PoO. */
    int         allow_ungranted_peers;
    /* SDP signaling transport. UDP is the default. */
    enum bowie_signal_backend {
        BOWIE_SIGNAL_BACKEND_UDP = 0,
        BOWIE_SIGNAL_BACKEND_METERED = 1
    } signal_backend;
    /* Required for Metered; use a publishable pk_ key and channel name. */
    const char *signal_metered_api_key;
    const char *signal_metered_channel;
    uint16_t    dht_port;
    uint16_t    nat_port;
    int         allow_server;

    const char *stun_host;
    uint16_t    stun_port;

    const char *turn_host;
    uint16_t    turn_port;
    const char *turn_user;
    const char *turn_pass;

    /* Optional local IPv4 address used for ICE sockets. */
    const char *nat_bind_address;

    /* Optional UDP rendezvous relay for SDP signaling. */
    const char *signal_relay_host;
    uint16_t    signal_relay_port;

    /* Optional persistent 32-byte Ed25519 seed. NULL generates a fresh identity. */
    const uint8_t *identity_seed;

    uint32_t    tunnel_mtu;

    /* Optional platform dataplane for decrypted source-side packets. */
    bowie_gateway_source_egress_fn source_egress;
    void       *source_egress_context;

    /* Bootstrap nodes are copied by bowie_engine_new(). Add them before start. */
    bowie_dht_bootstrap_t bootstrap[BOWIE_DHT_BOOTSTRAP_MAX];
    size_t                bootstrap_count;
} bowie_engine_config_t;

/*
 * ============================================================================
 * LIFECYCLE
 * ============================================================================
 */

void bowie_engine_default_config(bowie_engine_config_t *cfg);

bowie_error_t bowie_engine_new(const bowie_engine_config_t *cfg,
                               bowie_engine_t **out);

void bowie_engine_free(bowie_engine_t *e);

/*
 * ============================================================================
 * HOOKS
 * ============================================================================
 *
 * Install the hook set (Log, Event, Storage).
 *
 * The engine copies the hook set. The caller may free the set
 * after the call returns. The hook set must be installed before
 * bowie_engine_start().
 */
bowie_error_t bowie_engine_set_hooks(bowie_engine_t *e,
                                     const bowie_hooks_t *hooks);

/*
 * ============================================================================
 * START / STOP
 * ============================================================================
 */

/* Pass NULL for transport-only use without a packet tunnel. */
bowie_error_t bowie_engine_start(bowie_engine_t *e,
                                 bowie_tun_t *tun);

bowie_error_t bowie_engine_stop(bowie_engine_t *e);

/*
 * ============================================================================
 * SEARCH
 * ============================================================================
 */

bowie_error_t bowie_engine_search_peer(bowie_engine_t *e,
                                       const bowie_peer_id_t *peer_id,
                                       bowie_dht_node_t *out_node,
                                       uint32_t timeout_ms);

/* Room-based DHT rendezvous. The room string is SHA-1 hashed as the DHT key.
 * Room-mode handshake signatures include a domain-separated PoO challenge
 * bound to that hash; peers using a different room cannot authenticate. The
 * DHT endpoint remains an untrusted hint. A valid owner-issued grant is still
 * required unless allow_ungranted_peers is explicitly enabled. */
bowie_error_t bowie_engine_announce_room(bowie_engine_t *e,
                                         const char *room);
bowie_error_t bowie_engine_discover_room(bowie_engine_t *e,
                                         const char *room,
                                         bowie_dht_node_t *out_node,
                                         uint32_t timeout_ms);

/*
 * ============================================================================
 * CONNECT / ACCEPT / DISCONNECT
 * ============================================================================
 */

bowie_error_t bowie_engine_connect(bowie_engine_t *e,
                                   const bowie_peer_id_t *peer,
                                   uint32_t timeout_ms);
bowie_error_t bowie_engine_connect_room(bowie_engine_t *e,
                                        const char *room,
                                        uint32_t timeout_ms);

/* Connect to a peer using an explicitly exchanged LAN signalling endpoint.
 * The peer ID must be the stable ID displayed by the remote engine. */
bowie_error_t bowie_engine_connect_direct(bowie_engine_t *e,
                                         const bowie_peer_id_t *peer,
                                         const bowie_addr_t *signal_addr,
                                         uint32_t timeout_ms);

/* Connect by peer ID through the configured signaling relay. */
bowie_error_t bowie_engine_connect_relay(bowie_engine_t *e,
                                         const bowie_peer_id_t *peer,
                                         uint32_t timeout_ms);

/* Unpinned accept is disabled; use bowie_engine_accept_from(). */
bowie_error_t bowie_engine_accept(bowie_engine_t *e,
                                  uint32_t timeout_ms);

/* Accept only a peer whose signed Ed25519 identity hashes to expected_peer. */
bowie_error_t bowie_engine_accept_from(bowie_engine_t *e,
                                       const bowie_peer_id_t *expected_peer,
                                       uint32_t timeout_ms);
/* Accept an authenticated peer discovered through the configured room.
 * Requires authorize_discovered_peer to approve the verified identity. */
bowie_error_t bowie_engine_accept_discovered(bowie_engine_t *e,
                                             uint32_t timeout_ms);

bowie_error_t bowie_engine_disconnect(bowie_engine_t *e);
/* Revoke an issued grant. The grant is rejected by subsequent handshakes. */
bowie_error_t bowie_engine_revoke_grant(bowie_engine_t *e,
                                        const bowie_grant_id_t *grant_id);

/* Replace the active peer gateway's TUN descriptor without renegotiating the
 * peer session. The engine takes ownership of fd, including on failure. */
bowie_error_t bowie_engine_replace_tun_fd(bowie_engine_t *e, int fd);

/*
 * ============================================================================
 * BOOTSTRAP
 * ============================================================================
 *
 * Add a DHT bootstrap node. The host is a string (e.g., "1.2.3.4")
 * and the port is the DHT port (e.g., 6881). The engine copies
 * the host string.
 */
bowie_error_t bowie_engine_add_bootstrap(bowie_engine_t *e,
                                         const char *host,
                                         uint16_t port);

/*
 * ============================================================================
 * IDENTITY
 * ============================================================================
 */

void bowie_engine_public_id(const bowie_engine_t *e,
                            bowie_public_id_t *out);

void bowie_engine_peer_id(const bowie_engine_t *e,
                          bowie_peer_id_t *out);
/* Return the authenticated peer for the active tunnel. */
bowie_error_t bowie_engine_connected_peer_id(const bowie_engine_t *e,
                                            bowie_peer_id_t *out);

bowie_error_t bowie_engine_sign(bowie_engine_t *e,
                                const void *msg, size_t msg_len,
                                bowie_sign_signature_t *out);

/* Issue a peer-specific owner grant. ttl_ms is converted to wall-clock expiry. */
bowie_error_t bowie_engine_issue_grant(bowie_engine_t *e,
                                       const bowie_peer_id_t *subject,
                                       uint32_t permissions,
                                       uint64_t ttl_ms,
                                       bowie_grant_t *out);
/* Issue a grant with a signed cumulative source-egress byte limit. */
bowie_error_t bowie_engine_issue_limited_grant(bowie_engine_t *e,
                                               const bowie_peer_id_t *subject,
                                               uint32_t permissions,
                                               uint64_t ttl_ms,
                                               uint64_t max_egress_bytes,
                                               bowie_grant_t *out);

/* Install the grant this engine presents when requesting a source connection. */
bowie_error_t bowie_engine_set_grant(bowie_engine_t *e,
                                     const bowie_grant_t *grant);
void bowie_engine_clear_grant(bowie_engine_t *e);

/*
 * ============================================================================
 * STATE
 * ============================================================================
 */

typedef enum bowie_engine_state {
    BOWIE_ENGINE_STOPPED    = 0,
    BOWIE_ENGINE_STARTED    = 1,
    BOWIE_ENGINE_CONNECTING = 2,
    BOWIE_ENGINE_RUNNING    = 3
} bowie_engine_state_t;

bowie_engine_state_t bowie_engine_get_state(const bowie_engine_t *e);

const char *bowie_engine_state_name(bowie_engine_state_t state);

/*
 * ============================================================================
 * EVENTS
 * ============================================================================
 */

void bowie_engine_drain_events(bowie_engine_t *e);

int bowie_engine_poll_event(bowie_engine_t *e,
                            bowie_event_record_t *out);

/*
 * ============================================================================
 * INFO
 * ============================================================================
 */

uint16_t bowie_engine_dht_port(const bowie_engine_t *e);

uint16_t bowie_engine_signal_port(const bowie_engine_t *e);

size_t bowie_engine_dht_node_count(const bowie_engine_t *e);

/* Copy live tunnel gateway packet counters; a transport-only engine returns zeros. */
void bowie_engine_gateway_stats(const bowie_engine_t *e,
                                bowie_gateway_stats_t *out);

#ifdef __cplusplus
}
#endif

#endif /* BOWIE_ENGINE_ENGINE_H */
