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
 * BOWIE — GATEWAY
 * ============================================================================
 *
 * Packet forwarding between the Bowie tunnel and the Internet.
 *
 * The gateway reads packets from its tunnel fd, encrypts them
 * for the connected peer, and sends them over the NAT data
 * channel. Inbound peer packets are authenticated, decrypted,
 * and written to the tunnel fd.
 *
 * The gateway is not a NAT. The tunnel is point-to-point; the
 * gateway sees one peer on one side and the Internet on the
 * other. The operating system's routing table and conntrack do
 * the rest.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No tunnel. The tunnel is opened by the engine and
 *     supplied to the gateway.
 *   - No permission. The gateway trusts that the session was
 *     already authorized at layer 7. A packet that arrives
 *     without an authorized session is dropped.
 *   - No NAT. The gateway does not translate addresses. The
 *     operating system's routing and conntrack do that.
 *   - No DNS. The gateway forwards packets, not names.
 *   - No configuration of the host. The caller is responsible
 *     for ip_forward, iptables, and routing.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * The host network stack routes injected packets onward. This
 * module does not configure host forwarding, firewall, or NAT
 * rules. A single gateway instance serves one peer.
 *
 * The handle is opaque. The caller owns it, never sees its
 * layout, and frees it with bowie_gateway_close().
 *
 * The gateway does not own the tunnel. The tunnel is supplied
 * at open time and must remain valid for the lifetime of the
 * gateway. A caller that closes the tunnel before the gateway
 * is using it is a caller bug.
 *
 * The gateway does not own the session. The session is
 * supplied at start time. A caller that frees the session
 * before the gateway is using it is a caller bug.
 *
 * A gateway is a long-lived object. It is created when a peer
 * connects and destroyed when the peer disconnects. A busy
 * owner may have many gateways at once; each one is a small
 * amount of state.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <stdint.h>              uint32_t
 *   <stddef.h>              size_t
 *   "bowie/types.h"         bowie_gateway_t, bowie_tun_t,
 *                           bowie_session_t, bowie_addr_t
 *   "bowie/err.h"           bowie_error_t
 * ============================================================================
 */

#ifndef BOWIE_GATEWAY_GATEWAY_H
#define BOWIE_GATEWAY_GATEWAY_H

#include <stdint.h>
#include <stddef.h>

#include "bowie/types.h"
#include "bowie/err.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ============================================================================
 * CONFIGURATION
 * ============================================================================
 *
 * The config is a plain value struct. It is copied by
 * bowie_gateway_open(); the caller may free the struct after
 * the call returns.
 *
 * Zero-init the struct, then override the fields you need.
 * bowie_gateway_default_config() returns a sane starting
 * point.
 *
 * mtu
 *     The Maximum Transmission Unit the gateway assumes for
 *     the tunnel. A packet larger than this is dropped. Zero
 *     means use the tunnel default (BOWIE_TUN_MTU_TUNNEL).
 *
 * conntrack_capacity
 *     The maximum number of connections the gateway will
 *     track at once. Zero means use a built-in default
 *     (BOWIE_GATEWAY_CONNTRACK_DEFAULT).
 *
 * allow_private
 *     If 0, the gateway drops packets to private addresses
 *     (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16,
 *     127.0.0.0/8) and to link-local addresses. This is the
 *     default. A caller that wants the peer to see the
 *     owner's LAN sets it to 1.
 *
 * allow_ipv6
 *     If 1, the gateway forwards IPv6 packets as well as
 *     IPv4. The default is 0; IPv6 is opt-in because many
 *     owners do not have a working IPv6 uplink.
 *
 * source_gateway
 *     Set on the authenticated source endpoint. It enables
 *     destination filtering before client packets enter the
 *     owner's host network stack and applies the presenting
 *     grant's cumulative byte quota.
 */

#define BOWIE_GATEWAY_CONNTRACK_DEFAULT 1024

typedef int (*bowie_gateway_emit_fn)(void *context, const uint8_t *packet,
                                     size_t packet_len);
typedef int (*bowie_gateway_source_egress_fn)(void *context,
        const uint8_t *packet, size_t packet_len,
        bowie_gateway_emit_fn emit, void *emit_context);
typedef void (*bowie_gateway_quota_exceeded_fn)(void *context);
typedef int (*bowie_gateway_quota_save_fn)(void *context, uint64_t used);

typedef struct bowie_gateway_config {
    uint32_t mtu;
    uint32_t conntrack_capacity;
    int      allow_private;
    int      allow_ipv6;
    int      source_gateway;
    uint64_t source_grant_quota_bytes; /* zero means unlimited */
    uint64_t *source_grant_quota_used; /* optional persistent-in-engine counter */
    bowie_gateway_quota_save_fn source_quota_save;
    void    *source_quota_save_context;
    bowie_gateway_quota_exceeded_fn source_quota_exceeded;
    void    *source_quota_context;
    bowie_gateway_source_egress_fn source_egress;
    void    *source_egress_context;
} bowie_gateway_config_t;

/*
 * ============================================================================
 * LIFECYCLE
 * ============================================================================
 */

/*
 * Fill a config with default values.
 *
 * Defaults: mtu = 0 (use tunnel default), conntrack_capacity
 * = 0 (use built-in default), allow_private = 0,
 * allow_ipv6 = 0.
 *
 * Passing NULL is a no-op.
 */
void bowie_gateway_default_config(bowie_gateway_config_t *cfg);

/*
 * Open a gateway.
 *
 * The tunnel is supplied at open time and must remain valid
 * for the lifetime of the gateway. The session is supplied at
 * start time.
 *
 * On success, *out points to the new gateway handle.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NULL_ARG if out or tun is NULL.
 * Returns BOWIE_ERR_INVAL if the config is inconsistent.
 * Returns BOWIE_ERR_NOMEM if allocation fails.
 */
bowie_error_t bowie_gateway_open(bowie_gateway_t       **out,
                                  const bowie_gateway_config_t *cfg,
                                  bowie_tun_t           *tun);

/*
 * Close a gateway.
 *
 * Any active forwarding loop is stopped first. The tunnel is
 * not closed; the caller owns it. Passing NULL is a no-op.
 */
void bowie_gateway_close(bowie_gateway_t *gw);

/*
 * ============================================================================
 * START / STOP
 * ============================================================================
 *
 * A gateway is opened once and started for each peer. A single
 * gateway can be started and stopped many times, with a
 * different session each time. This is the normal shape on a
 * router: one gateway, many peers.
 */

/*
 * Start forwarding for a session.
 *
 * The session must have been authorized at layer 7. The
 * gateway does not check permission; it trusts that the caller
 * has already done so.
 *
 * The gateway spawns a forwarding loop in its own thread. The
 * call returns when the loop has started, not when it has
 * finished.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NULL_ARG if gw or session is NULL.
 * Returns BOWIE_ERR_STATE if the gateway is already started.
 * Returns BOWIE_ERR_INTERNAL if the loop could not be started.
 */
bowie_error_t bowie_gateway_start(bowie_gateway_t *gw,
                                   bowie_session_t *session,
                                   bowie_nat_t *nat);

/*
 * Stop forwarding.
 *
 * The forwarding loop is asked to exit and the call waits for
 * it to do so. Any in-flight packets are dropped.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NULL_ARG if gw is NULL.
 * Returns BOWIE_ERR_NOT_STARTED if the gateway is not started.
 */
bowie_error_t bowie_gateway_stop(bowie_gateway_t *gw);

/*
 * ============================================================================
 * STATISTICS
 * ============================================================================
 */

/*
 * A small statistics block that the gateway updates as it
 * forwards. A caller that wants to display or log the
 * counters reads them with bowie_gateway_stats().
 */

typedef struct bowie_gateway_stats {
    uint64_t packets_in;
    uint64_t packets_out;
    uint64_t bytes_in;
    uint64_t bytes_out;
    uint64_t drops_private;
    uint64_t drops_too_large;
    uint64_t drops_no_session;
    uint64_t drops_no_conntrack;
    uint64_t packets_dropped;
} bowie_gateway_stats_t;

/*
 * Copy the current statistics into the caller's struct.
 *
 * The counters are copied under the gateway lock.
 *
 * Passing NULL for either argument is a no-op.
 */
void bowie_gateway_stats(const bowie_gateway_t *gw,
                         bowie_gateway_stats_t *out);

/*
 * ============================================================================
 * END OF GATEWAY
 * ============================================================================
 */

#ifdef __cplusplus
}
#endif

#endif /* BOWIE_GATEWAY_GATEWAY_H */
