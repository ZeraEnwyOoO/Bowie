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
 * BOWIE — GATEWAY (IMPLEMENTATION)
 * ============================================================================
 *
 * Implementation of the gateway declared in gateway/gateway.h.
 *
 * The gateway moves IP packets between a platform tunnel and
 * the peer's encrypted libjuice data channel. The loop runs in
 * its own thread while the gateway is started.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No tunnel creation. The caller supplies a packet fd.
 *   - No host forwarding or address translation. The platform
 *     must configure its routing and forwarding policy.
 *   - No identity check. The engine authenticates the pinned
 *     peer before starting this gateway.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * The gateway is opened once and started for each peer. A
 * single gateway can be started and stopped many times, with a
 * different session each time.
 *
 * The loop reads IP packets from the tunnel, encrypts them with
 * the session keys, and sends them over NAT. Received packets
 * are authenticated, decrypted, and injected into the tunnel.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <pthread.h>              pthread_t, pthread_mutex_t
 *   <stdlib.h>               calloc, free
 *   <string.h>               memset
 *   <unistd.h>               read, write
 *   "bowie/types.h"          types
 *   "bowie/err.h"            errors
 *   "gateway/gateway.h"      declarations
 * ============================================================================
 */

#include <pthread.h>
#include <poll.h>
#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "bowie/types.h"
#include "bowie/err.h"
#include "gateway/gateway.h"
#include "nat/nat.h"
#include "security/session.h"
#include "tunnel/mtu.h"
#include "tunnel/tun.h"
#include "core/internal/diag_json.h"
#include "core/internal/time.h"

/*
 * ============================================================================
 * HANDLE
 * ============================================================================
 */

struct bowie_gateway {
    bowie_gateway_config_t cfg;
    bowie_tun_t           *tun;
    bowie_session_t       *session;
    bowie_nat_t           *nat;

    int                    started;

    pthread_t              thread;
    pthread_mutex_t        lock;
    pthread_mutex_t        send_lock;
    pthread_mutex_t        quota_lock;
    int                    stop_requested;

    bowie_gateway_stats_t  stats;
    uint64_t               quota_used;
    int                    quota_exceeded_notified;
};

/* Reserve bytes before forwarding so concurrent directions cannot overshoot
 * the signed per-grant cap. The caller notifies the engine after forwarding. */
static int gateway_quota_reserve(bowie_gateway_t *gw, size_t bytes, int *reached)
{
    int allowed = 0;
    if (reached != NULL) *reached = 0;
    if (gw == NULL || !gw->cfg.source_gateway) return 1;
    pthread_mutex_lock(&gw->quota_lock);
    if (gw->cfg.source_grant_quota_bytes == 0u) {
        allowed = 1;
    } else if (gw->quota_used <= gw->cfg.source_grant_quota_bytes &&
               (uint64_t)bytes <= gw->cfg.source_grant_quota_bytes - gw->quota_used) {
        uint64_t next_used = gw->quota_used + (uint64_t)bytes;
        if (gw->cfg.source_quota_save != NULL &&
            !gw->cfg.source_quota_save(gw->cfg.source_quota_save_context,
                                       next_used)) {
            if (!gw->quota_exceeded_notified && reached != NULL) *reached = 1;
            gw->quota_exceeded_notified = 1;
            pthread_mutex_unlock(&gw->quota_lock);
            return 0;
        }
        gw->quota_used = next_used;
        if (gw->cfg.source_grant_quota_used != NULL)
            __atomic_store_n(gw->cfg.source_grant_quota_used, gw->quota_used,
                             __ATOMIC_RELEASE);
        allowed = 1;
        if (gw->cfg.source_grant_quota_bytes != 0u &&
            gw->quota_used >= gw->cfg.source_grant_quota_bytes) {
            if (!gw->quota_exceeded_notified && reached != NULL) *reached = 1;
            gw->quota_exceeded_notified = 1;
        }
    } else {
        if (!gw->quota_exceeded_notified && reached != NULL) *reached = 1;
        gw->quota_exceeded_notified = 1;
    }
    pthread_mutex_unlock(&gw->quota_lock);
    return allowed;
}

static void gateway_quota_notify(bowie_gateway_t *gw, int reached)
{
    if (reached && gw != NULL && gw->cfg.source_quota_exceeded != NULL)
        gw->cfg.source_quota_exceeded(gw->cfg.source_quota_context);
}

static int gateway_emit_peer(void *context, const uint8_t *packet,
                             size_t packet_len)
{
    bowie_gateway_t *gw = (bowie_gateway_t *)context;
    uint8_t encrypted[BOWIE_TUN_MTU_MAX + BOWIE_SESSION_OVERHEAD_LEN];
    size_t encrypted_len = 0u;
    bowie_error_t rc;
    long sent;
    int quota_reached = 0;
    if (gw == NULL || packet == NULL || packet_len == 0u ||
        packet_len > BOWIE_TUN_MTU_MAX || gw->session == NULL || gw->nat == NULL)
        return 0;
    if (!gateway_quota_reserve(gw, packet_len, &quota_reached)) {
        gateway_quota_notify(gw, quota_reached);
        return 0;
    }
    pthread_mutex_lock(&gw->send_lock);
    rc = bowie_session_encrypt(gw->session, packet, packet_len, encrypted,
                               sizeof(encrypted), &encrypted_len);
    sent = rc == BOWIE_OK ? bowie_nat_send(gw->nat, encrypted, encrypted_len) : (long)rc;
    pthread_mutex_unlock(&gw->send_lock);
    gateway_quota_notify(gw, quota_reached);
    return rc == BOWIE_OK && sent == (long)encrypted_len;
}

/*
 * ============================================================================
 * FORWARDING LOOP
 * ============================================================================
 *
 * Packets read from TUN are authenticated-encrypted and sent
 * through the established NAT data channel. Received data is
 * authenticated-decrypted by gateway_nat_recv() and injected
 * into TUN.
 */

static void gateway_nat_recv(void *ctx, const uint8_t *data, size_t len)
{
    bowie_gateway_t *gw = (bowie_gateway_t *)ctx;
    uint8_t packet[BOWIE_TUN_MTU_MAX];
    size_t packet_len = 0u;
    bowie_error_t decrypt_rc;

    if (gw == NULL || data == NULL || gw->session == NULL || gw->tun == NULL) return;
    decrypt_rc = bowie_session_decrypt(gw->session, data, len, packet,
                                       sizeof(packet), &packet_len);
    if (decrypt_rc != BOWIE_OK) {
        pthread_mutex_lock(&gw->lock);
        gw->stats.packets_dropped++;
        pthread_mutex_unlock(&gw->lock);
        {
            char details[160];
            (void)snprintf(details, sizeof(details),
                           "{\"direction\":\"in\",\"encrypted_bytes\":%zu,\"reason\":\"decrypt_failed\",\"error\":%d}",
                           len, (int)decrypt_rc);
            bowie_diag_json_emit("WARN", "Gateway", "GATEWAY_PACKET_DROPPED", NULL, details);
        }
        return;
    }

    /* The source endpoint must never turn an authorized Internet tunnel
     * into implicit access to the owner's host or LAN. Filter destination
     * addresses before injecting a client packet into the host stack. */
    if (gw->cfg.source_gateway && packet_len != 0u) {
        uint8_t version = packet[0] >> 4;
        int blocked = 0;
        if (version == 4u) {
            if (packet_len < 20u || (size_t)(packet[0] & 0x0fu) * 4u > packet_len) {
                blocked = 1;
            } else if (!gw->cfg.allow_private) {
                const uint8_t *d = packet + 16;
                blocked = d[0] == 0u || d[0] == 10u || d[0] == 127u ||
                    d[0] >= 224u || (d[0] == 100u && (d[1] & 0xc0u) == 64u) ||
                    (d[0] == 169u && d[1] == 254u) ||
                    (d[0] == 172u && (d[1] & 0xf0u) == 16u) ||
                    (d[0] == 192u && d[1] == 168u) ||
                    (d[0] == 192u && d[1] == 0u && (d[2] == 0u || d[2] == 2u)) ||
                    (d[0] == 192u && d[1] == 88u && d[2] == 99u) ||
                    (d[0] == 198u && (d[1] == 18u || d[1] == 19u)) ||
                    (d[0] == 198u && d[1] == 51u && d[2] == 100u) ||
                    (d[0] == 203u && d[1] == 0u && d[2] == 113u);
            }
        } else if (version == 6u) {
            if (packet_len < 40u || !gw->cfg.allow_ipv6) {
                blocked = 1;
            } else if (!gw->cfg.allow_private) {
                const uint8_t *d = packet + 24;
                blocked = (d[0] == 0u && d[1] == 0u && d[2] == 0u &&
                           d[3] == 0u && d[4] == 0u && d[5] == 0u &&
                           d[6] == 0u && d[7] == 0u && d[8] == 0u &&
                           d[9] == 0u && d[10] == 0u && d[11] == 0u &&
                           d[12] == 0u && d[13] == 0u && d[14] == 0u) ||
                    (d[0] & 0xfeu) == 0xfcu || (d[0] == 0xfeu && (d[1] & 0xc0u) == 0x80u) ||
                    d[0] == 0xffu ||
                    (d[0] == 0x20u && d[1] == 0x01u && d[2] == 0x0du && d[3] == 0xb8u);
            }
        } else {
            blocked = 1;
        }
        if (blocked) {
            pthread_mutex_lock(&gw->lock);
            gw->stats.packets_dropped++;
            if (version == 4u && !gw->cfg.allow_private) gw->stats.drops_private++;
            pthread_mutex_unlock(&gw->lock);
            bowie_diag_json_emit("WARN", "Gateway", "GATEWAY_PACKET_DROPPED", NULL,
                                 "{\"direction\":\"in\",\"reason\":\"egress_policy\"}");
            return;
        }
    }
    long written;
    if (gw->cfg.source_gateway) {
        int forwarded = 0;
        int quota_reached = 0;
        if (!gateway_quota_reserve(gw, packet_len, &quota_reached)) {
            gateway_quota_notify(gw, quota_reached);
            pthread_mutex_lock(&gw->lock);
            gw->stats.packets_dropped++;
            pthread_mutex_unlock(&gw->lock);
            bowie_diag_json_emit("WARN", "Gateway", "GATEWAY_QUOTA_EXCEEDED", NULL,
                                 "{\"direction\":\"source_egress\",\"reason\":\"grant_byte_limit\"}");
            return;
        }
        if (gw->cfg.source_egress != NULL) {
            forwarded = gw->cfg.source_egress(gw->cfg.source_egress_context,
                packet, packet_len, gateway_emit_peer, gw);
        } else {
            long injected = bowie_tun_write(gw->tun, packet, packet_len);
            forwarded = injected == (long)packet_len;
        }
        gateway_quota_notify(gw, quota_reached);
        written = forwarded ? (long)packet_len : -1;
    } else {
        written = bowie_tun_write(gw->tun, packet, packet_len);
    }
    pthread_mutex_lock(&gw->lock);
    if (written == (long)packet_len) {
        gw->stats.packets_in++;
        gw->stats.bytes_in += packet_len;
    } else {
        gw->stats.packets_dropped++;
    }
    pthread_mutex_unlock(&gw->lock);
    if (written == (long)packet_len) {
        char details[96];
        (void)snprintf(details, sizeof(details),
                       "{\"direction\":\"in\",\"bytes\":%zu}", packet_len);
        bowie_diag_json_emit("DEBUG", "Gateway", "GATEWAY_PACKET_FORWARDED", NULL, details);
    } else {
        char details[160];
        (void)snprintf(details, sizeof(details),
                       "{\"direction\":\"in\",\"bytes\":%zu,\"write_result\":%ld,\"reason\":\"%s\"}",
                       packet_len, written,
                       gw->cfg.source_gateway ? "source_egress_failed" : "tun_write_failed");
        bowie_diag_json_emit("WARN", "Gateway", "GATEWAY_PACKET_DROPPED", NULL, details);
    }
}

static void *forward_loop(void *arg)
{
    bowie_gateway_t *gw = (bowie_gateway_t *)arg;
    uint8_t packet[BOWIE_TUN_MTU_MAX];
    uint8_t encrypted[BOWIE_TUN_MTU_MAX + BOWIE_SESSION_OVERHEAD_LEN];
    struct pollfd pfd;

    pfd.fd = bowie_tun_fd(gw->tun);
    pfd.events = POLLIN;

    while (1) {
        int stop;

        pthread_mutex_lock(&gw->lock);
        stop = gw->stop_requested;
        pthread_mutex_unlock(&gw->lock);
        if (stop) {
            break;
        }

        int ready = poll(&pfd, 1, 100);
        if (ready < 0) {
            if (errno == EINTR) continue;
            char details[96];
            (void)snprintf(details, sizeof(details),
                           "{\"reason\":\"tun_poll_failed\",\"errno\":%d}", errno);
            bowie_diag_json_emit("ERROR", "Gateway", "GATEWAY_LOOP_STOPPED", NULL, details);
            break;
        }
        if (ready == 0 || !(pfd.revents & POLLIN)) continue;

        long got = bowie_tun_read(gw->tun, packet, sizeof(packet));
        if (got < 0) {
            char details[96];
            (void)snprintf(details, sizeof(details),
                           "{\"reason\":\"tun_read_failed\",\"error\":%ld}", got);
            bowie_diag_json_emit("WARN", "Gateway", "GATEWAY_PACKET_DROPPED", NULL, details);
            continue;
        }
        if (got == 0) continue;

        int quota_reached = 0;
        if (gw->cfg.source_gateway &&
            !gateway_quota_reserve(gw, (size_t)got, &quota_reached)) {
            gateway_quota_notify(gw, quota_reached);
            pthread_mutex_lock(&gw->lock);
            gw->stats.packets_dropped++;
            pthread_mutex_unlock(&gw->lock);
            bowie_diag_json_emit("WARN", "Gateway", "GATEWAY_QUOTA_EXCEEDED", NULL,
                                 "{\"direction\":\"source_reply\",\"reason\":\"grant_byte_limit\"}");
            continue;
        }
        size_t encrypted_len = 0u;
        pthread_mutex_lock(&gw->send_lock);
        bowie_error_t rc = bowie_session_encrypt(gw->session, packet,
            (size_t)got, encrypted, sizeof(encrypted), &encrypted_len);
        long sent = (rc == BOWIE_OK) ? bowie_nat_send(gw->nat, encrypted, encrypted_len) : (long)rc;
        pthread_mutex_unlock(&gw->send_lock);
        gateway_quota_notify(gw, quota_reached);

        pthread_mutex_lock(&gw->lock);
        if (sent == (long)encrypted_len) {
            gw->stats.packets_out++;
            gw->stats.bytes_out += (size_t)got;
        } else {
            gw->stats.packets_dropped++;
        }
        pthread_mutex_unlock(&gw->lock);

        if (sent == (long)encrypted_len) {
            char details[96];
            (void)snprintf(details, sizeof(details),
                           "{\"direction\":\"out\",\"bytes\":%ld,\"encrypted_bytes\":%zu}",
                           got, encrypted_len);
            bowie_diag_json_emit("DEBUG", "Gateway", "GATEWAY_PACKET_FORWARDED", NULL, details);
        } else {
            char details[160];
            (void)snprintf(details, sizeof(details),
                           "{\"direction\":\"out\",\"bytes\":%ld,\"reason\":\"%s\",\"error\":%ld}",
                           got, rc != BOWIE_OK ? "encrypt_failed" : "transport_send_failed",
                           rc != BOWIE_OK ? (long)rc : sent);
            bowie_diag_json_emit("WARN", "Gateway", "GATEWAY_PACKET_DROPPED", NULL, details);
        }
    }

    return NULL;
}

/*
 * ============================================================================
 * CONFIG
 * ============================================================================
 */

void bowie_gateway_default_config(bowie_gateway_config_t *cfg)
{
    if (cfg == NULL) {
        return;
    }

    memset(cfg, 0, sizeof(*cfg));

    cfg->mtu                 = 0;
    cfg->conntrack_capacity  = 0;
    cfg->allow_private       = 0;
    cfg->allow_ipv6          = 0;
    cfg->source_gateway      = 0;
    cfg->source_grant_quota_bytes = 0u;
    cfg->source_grant_quota_used = NULL;
    cfg->source_quota_save = NULL;
    cfg->source_quota_save_context = NULL;
    cfg->source_quota_exceeded = NULL;
    cfg->source_quota_context = NULL;
    cfg->source_egress = NULL;
    cfg->source_egress_context = NULL;
}

/*
 * ============================================================================
 * LIFECYCLE
 * ============================================================================
 */

bowie_error_t bowie_gateway_open(bowie_gateway_t              **out,
                                  const bowie_gateway_config_t  *cfg,
                                  bowie_tun_t                   *tun)
{
    bowie_gateway_t *gw;

    if (out == NULL || cfg == NULL || tun == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }

    *out = NULL;

    if (cfg->allow_private != 0 && cfg->allow_private != 1) {
        return BOWIE_ERR_INVAL;
    }
    if (cfg->allow_ipv6 != 0 && cfg->allow_ipv6 != 1) {
        return BOWIE_ERR_INVAL;
    }
    if (cfg->source_gateway != 0 && cfg->source_gateway != 1) {
        return BOWIE_ERR_INVAL;
    }

    gw = (bowie_gateway_t *)calloc(1, sizeof(*gw));

    if (gw == NULL) {
        return BOWIE_ERR_NOMEM;
    }

    if (pthread_mutex_init(&gw->lock, NULL) != 0) {
        free(gw);
        return BOWIE_ERR_INTERNAL;
    }

    if (pthread_mutex_init(&gw->send_lock, NULL) != 0) {
        pthread_mutex_destroy(&gw->lock);
        free(gw);
        return BOWIE_ERR_INTERNAL;
    }
    if (pthread_mutex_init(&gw->quota_lock, NULL) != 0) {
        pthread_mutex_destroy(&gw->send_lock);
        pthread_mutex_destroy(&gw->lock);
        free(gw);
        return BOWIE_ERR_INTERNAL;
    }

    gw->cfg     = *cfg;
    gw->tun     = tun;
    gw->session = NULL;
    gw->nat = NULL;
    gw->started = 0;
    gw->stop_requested = 0;
    gw->quota_used = cfg->source_grant_quota_used != NULL
        ? __atomic_load_n(cfg->source_grant_quota_used, __ATOMIC_ACQUIRE) : 0u;

    *out = gw;

    return BOWIE_OK;
}

void bowie_gateway_close(bowie_gateway_t *gw)
{
    if (gw == NULL) {
        return;
    }

    if (gw->started) {
        (void)bowie_gateway_stop(gw);
    }

    pthread_mutex_destroy(&gw->lock);
    pthread_mutex_destroy(&gw->send_lock);
    pthread_mutex_destroy(&gw->quota_lock);
    free(gw);
}

/*
 * ============================================================================
 * START / STOP
 * ============================================================================
 */

bowie_error_t bowie_gateway_start(bowie_gateway_t *gw,
                                   bowie_session_t *session,
                                   bowie_nat_t *nat)
{
    if (gw == NULL || session == NULL || nat == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }

    if (gw->started) {
        return BOWIE_ERR_STATE;
    }

    gw->session        = session;
    gw->nat            = nat;
    gw->stop_requested = 0;

    bowie_error_t rc = bowie_nat_set_recv(nat, gateway_nat_recv, gw);
    if (rc != BOWIE_OK) {
        gw->session = NULL;
        gw->nat = NULL;
        return rc;
    }

    if (pthread_create(&gw->thread, NULL, forward_loop, gw) != 0) {
        (void)bowie_nat_set_recv(nat, NULL, NULL);
        gw->session = NULL;
        gw->nat = NULL;
        return BOWIE_ERR_INTERNAL;
    }

    gw->started = 1;

    return BOWIE_OK;
}

bowie_error_t bowie_gateway_stop(bowie_gateway_t *gw)
{
    if (gw == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }

    if (!gw->started) {
        return BOWIE_ERR_NOT_STARTED;
    }

    pthread_mutex_lock(&gw->lock);
    gw->stop_requested = 1;
    pthread_mutex_unlock(&gw->lock);

    if (gw->nat != NULL) {
        (void)bowie_nat_set_recv(gw->nat, NULL, NULL);
    }

    pthread_join(gw->thread, NULL);

    gw->started = 0;
    gw->session = NULL;
    gw->nat = NULL;

    return BOWIE_OK;
}

/*
 * ============================================================================
 * STATISTICS
 * ============================================================================
 */

void bowie_gateway_stats(const bowie_gateway_t *gw,
                         bowie_gateway_stats_t *out)
{
    if (gw == NULL || out == NULL) {
        return;
    }

    pthread_mutex_lock((pthread_mutex_t *)&gw->lock);
    *out = gw->stats;
    pthread_mutex_unlock((pthread_mutex_t *)&gw->lock);
}

/*
 * ============================================================================
 * END OF GATEWAY IMPLEMENTATION
 * ============================================================================
 */
