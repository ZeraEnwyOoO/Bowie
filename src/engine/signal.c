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
 * BOWIE — ENGINE SIGNALING CHANNEL (IMPLEMENTATION)
 * ============================================================================
 *
 * Implementation of the UDP signaling channel declared in
 * engine/internal/signal.h.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No NAT. The channel carries SDP blobs; the NAT layer
 *     produces and consumes them. The channel does not parse
 *     an SDP blob; it treats the frame's payload as opaque.
 *   - No handshake. The channel is unencrypted; the
 *     handshake that authenticates the peer runs over the
 *     NAT connection, not over the channel.
 *   - No retransmission. UDP is best-effort.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * The signaling thread is a poll-and-recv loop. The socket
 * is opened in non-blocking mode, so poll() is what makes
 * the loop efficient: it sleeps until a packet arrives or
 * the poll timeout expires.
 *
 * The thread does not hold the engine lock for long. It
 * takes the lock to update the peer's signaling address,
 * then releases it before dispatching to the NAT layer.
 * The NAT layer's own callbacks take their own locks; the
 * two locks are never taken in opposite orders, so there is
 * no deadlock.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <errno.h>                   errno
 *   <fcntl.h>                   fcntl, O_NONBLOCK
 *   <poll.h>                    poll, POLLIN
 *   <pthread.h>                 pthread_create, pthread_join
 *   <string.h>                  memcpy, memset
 *   <sys/socket.h>              socket, bind, recvfrom, sendto
 *   <netinet/in.h>              sockaddr_in, INADDR_ANY
 *   <arpa/inet.h>               htonl, htons, ntohs
 *   <unistd.h>                  close
 *   "bowie/types.h"             bowie_addr_t
 *   "bowie/err.h"               error codes
 *   "proto/framing.h"           frame header, frame encode/decode
 *   "engine/internal/engine.h"  struct bowie_engine
 *   "engine/internal/signal.h"  declarations
 * ============================================================================
 */

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>

#include "bowie/types.h"
#include "bowie/err.h"
#include "proto/framing.h"
#include "core/internal/time.h"
#include "engine/internal/engine.h"
#include "engine/internal/signal.h"
#include "engine/internal/diag.h"
#include "engine/internal/signal_relay.h"

/*
 * ============================================================================
 * INTERNAL — ADDRESS CONVERSION
 * ============================================================================
 */

static int addr_to_sockaddr_in(const bowie_addr_t *addr,
                               struct sockaddr_in *out)
{
    if (addr == NULL || out == NULL) {
        return 0;
    }
    if (addr->family != BOWIE_AF_INET) {
        return 0;
    }

    memset(out, 0, sizeof(*out));
    out->sin_family = AF_INET;
    memcpy(&out->sin_addr, addr->addr, 4);
    out->sin_port = htons(addr->port);
    return 1;
}

static int prepare_sdp_candidate_routes(bowie_engine_t *e,
                                        const uint8_t *data, size_t len)
{
    size_t offset = 0u;
    if (e->cfg.prepare_underlay_address == NULL) return 1;
    while (offset < len) {
        size_t end = offset;
        char line[1024];
        while (end < len && data[end] != '\n' && data[end] != '\r') ++end;
        size_t line_len = end - offset;
        if (line_len < sizeof(line) && line_len > 12u) {
            memcpy(line, data + offset, line_len);
            line[line_len] = '\0';
            if (strncmp(line, "a=candidate:", 12u) == 0) {
                char *save = NULL;
                char *token = strtok_r(line + 12u, " \t", &save);
                unsigned field = 0u;
                char *address = NULL;
                while (token != NULL) {
                    if (field == 4u) { address = token; break; }
                    ++field;
                    token = strtok_r(NULL, " \t", &save);
                }
                if (address != NULL) {
                    uint8_t binary[16];
                    if (inet_pton(AF_INET, address, binary) == 1) {
                        if (!e->cfg.prepare_underlay_address(e->cfg.underlay_context,
                                                             AF_INET, binary, 4u)) return 0;
                    } else if (inet_pton(AF_INET6, address, binary) == 1) {
                        if (!e->cfg.prepare_underlay_address(e->cfg.underlay_context,
                                                             AF_INET6, binary, 16u)) return 0;
                    }
                }
            }
        }
        offset = end;
        while (offset < len && (data[offset] == '\n' || data[offset] == '\r')) ++offset;
    }
    return 1;
}

static void sockaddr_in_to_addr(const struct sockaddr_in *sin,
                                bowie_addr_t *out)
{
    if (sin == NULL || out == NULL) {
        return;
    }

    memset(out, 0, sizeof(*out));
    out->family = BOWIE_AF_INET;
    memcpy(out->addr, &sin->sin_addr, 4);
    out->port = ntohs(sin->sin_port);
}

/*
 * ============================================================================
 * INTERNAL — DISPATCH
 * ============================================================================
 */

static void dispatch_frame(bowie_engine_t *e,
                           const uint8_t *frame_buf,
                           size_t frame_len,
                           const struct sockaddr_in *from,
                           const uint8_t *relay_source)
{
    bowie_span_t payload;
    bowie_error_t rc;
    int inbound;

    if (e == NULL || frame_buf == NULL || from == NULL) {
        return;
    }
    if (e->nat == NULL) {
        bowie_engine_diag("BowieSignal", "dropped frame: NAT backend is not initialized");
        return;
    }

    if (relay_source != NULL) {
        const bowie_peer_id_t *expected = e->inbound_offer
            ? &e->inbound_peer_id : &e->peer.peer_id;
        if (memcmp(relay_source, expected->bytes, BOWIE_PEER_ID_LEN) != 0) {
            bowie_diag_json_emit("WARN", "Signaling", "RELAY_PEER_MISMATCH", NULL,
                                 "{\"reason\":\"unexpected_source_peer\"}");
            return;
        }
    }

    rc = bowie_proto_frame_unwrap(frame_buf, frame_len, &payload);
    if (rc != BOWIE_OK) {
        bowie_engine_diag("BowieSignal", "discarded malformed signal frame (%zu bytes, error %d)",
                          frame_len, (int)rc);
        {
            char details[160];
            (void)snprintf(details, sizeof(details),
                "{\"source_ip\":\"%u.%u.%u.%u\",\"source_port\":%u,\"frame_bytes\":%zu,\"error_code\":%d}",
                (unsigned)((const uint8_t *)&from->sin_addr)[0],
                (unsigned)((const uint8_t *)&from->sin_addr)[1],
                (unsigned)((const uint8_t *)&from->sin_addr)[2],
                (unsigned)((const uint8_t *)&from->sin_addr)[3],
                (unsigned)ntohs(from->sin_port), frame_len, (int)rc);
            bowie_diag_json_emit("WARN", "Signaling", "SIGNAL_FRAME_REJECTED",
                                 NULL, details);
        }
        return;
    }
    if (e->cfg.prepare_underlay_address != NULL &&
        (!e->cfg.prepare_underlay_address(e->cfg.underlay_context, AF_INET,
                                          (const uint8_t *)&from->sin_addr, 4u) ||
         !prepare_sdp_candidate_routes(e, payload.data, payload.len))) {
        bowie_engine_diag("BowieSignal", "dropped signaling frame because an underlay route could not be installed");
        return;
    }

    bowie_engine_diag("BowieSignal", "received signal frame (%zu bytes, payload %zu) from %u.%u.%u.%u:%u",
                      frame_len, payload.len,
                      (unsigned)((const uint8_t *)&from->sin_addr)[0],
                      (unsigned)((const uint8_t *)&from->sin_addr)[1],
                      (unsigned)((const uint8_t *)&from->sin_addr)[2],
                      (unsigned)((const uint8_t *)&from->sin_addr)[3],
                      (unsigned)ntohs(from->sin_port));
    {
        char details[256];
        char peer_hex[BOWIE_PEER_ID_LEN * 2u + 1u];
        bowie_peer_id_t peer_id;
        pthread_mutex_lock(&e->lock);
        peer_id = e->peer.peer_id;
        pthread_mutex_unlock(&e->lock);
        const char *peer_value = NULL;
        if (!bowie_peer_id_is_zero(&peer_id)) {
            bowie_diag_hex(peer_id.bytes, BOWIE_PEER_ID_LEN,
                           peer_hex, sizeof(peer_hex));
            peer_value = peer_hex;
        }
        (void)snprintf(details, sizeof(details),
            "{\"source_ip\":\"%u.%u.%u.%u\",\"source_port\":%u,\"bytes\":%zu,\"candidate_count\":%zu}",
            (unsigned)((const uint8_t *)&from->sin_addr)[0],
            (unsigned)((const uint8_t *)&from->sin_addr)[1],
            (unsigned)((const uint8_t *)&from->sin_addr)[2],
            (unsigned)((const uint8_t *)&from->sin_addr)[3],
            (unsigned)ntohs(from->sin_port), payload.len,
            bowie_diag_candidate_count(payload.data, payload.len));
        bowie_diag_json_emit("INFO", "Signaling",
            bowie_diag_sdp_event(payload.data, payload.len), peer_value, details);
        if (bowie_diag_candidate_count(payload.data, payload.len) > 0u)
            bowie_diag_json_emit("DEBUG", "Signaling", "SIGNAL_CANDIDATE_RECEIVED",
                                  peer_value, details);
    }

    /*
     * Update the peer's signaling address. The lock is taken
     * for this short update and released before the NAT
     * call.
     */
    pthread_mutex_lock(&e->lock);
    inbound = e->inbound_offer;
    if (inbound) {
        e->peer_signal_addr = *from;
        e->peer_signal_addr_valid = 1;
    } else if (!e->peer_signal_addr_valid) {
        e->peer_signal_addr = *from;
        e->peer_signal_addr_valid = 1;
    }
    pthread_mutex_unlock(&e->lock);

    /*
     * Hand the payload to the NAT layer.
     */
    rc = bowie_nat_signal_recv(e->nat, payload.data, payload.len);
    bowie_engine_diag("BowieSignal", "NAT backend processed incoming signal (rc=%d)", (int)rc);
    if (rc != BOWIE_OK) {
        char details[96];
        (void)snprintf(details, sizeof(details),
                       "{\"payload_bytes\":%zu,\"error_code\":%d}", payload.len, (int)rc);
        bowie_diag_json_emit("WARN", "Signaling", "SIGNAL_DESCRIPTION_REJECTED",
                             NULL, details);
    }
    if (inbound) {
        pthread_mutex_lock(&e->lock);
        if (rc == BOWIE_OK) {
            pthread_cond_broadcast(&e->nat_cond);
        } else {
            e->peer_signal_addr_valid = 0;
        }
        pthread_mutex_unlock(&e->lock);
    }
}

static void metered_on_message(void *context, const uint8_t *peer_id,
                               const uint8_t *payload, size_t payload_len)
{
    bowie_engine_t *e = context;
    struct sockaddr_in from;
    uint8_t frame[BOWIE_ENGINE_SIGNAL_BUF_MAX];
    size_t frame_len = 0u;
    bowie_span_t span;
    if (e == NULL || peer_id == NULL) return;
    span.data = payload;
    span.len = payload_len;
    if (bowie_proto_frame_wrap(span, frame, sizeof(frame), &frame_len) != BOWIE_OK)
        return;
    memset(&from, 0, sizeof(from));
    from.sin_family = AF_INET;
    from.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    dispatch_frame(e, frame, frame_len, &from, peer_id);
}

static void metered_on_turn_server(void *context, const char *host,
                                   uint16_t port, const char *username,
                                   const char *credential)
{
    bowie_engine_t *e = context;
    if (e == NULL || e->nat == NULL) return;
    bowie_error_t rc = bowie_nat_add_turn_server(e->nat, host, port,
                                                  username, credential);
    bowie_engine_diag("Metered", "received TURN relay %s:%u (result=%d)", host,
                      (unsigned)port, (int)rc);
}

static void metered_on_presence(void *context, size_t peer_count)
{
    (void)context;
    bowie_engine_diag("Metered", "channel presence snapshot/change: %zu peers joined",
                      peer_count);
}

static void signal_relay_register(bowie_engine_t *e)
{
    uint8_t packet[BOWIE_SIGNAL_RELAY_HEADER_LEN];
    size_t packet_len = 0u;
    if (e == NULL || !e->signal_relay_enabled) return;
    if (!bowie_signal_relay_encode(packet, sizeof(packet),
            BOWIE_SIGNAL_RELAY_REGISTER, e->own_peer_id.bytes, NULL,
            NULL, 0u, &packet_len)) return;
    ssize_t sent = sendto(e->signal_fd, packet, packet_len, 0,
                          (struct sockaddr *)&e->signal_relay_addr,
                          sizeof(e->signal_relay_addr));
    char details[80];
    (void)snprintf(details, sizeof(details),
                   "{\"sent\":%s,\"port\":%u}",
                   sent == (ssize_t)packet_len ? "true" : "false",
                   (unsigned)ntohs(e->signal_relay_addr.sin_port));
    bowie_diag_json_emit(sent == (ssize_t)packet_len ? "INFO" : "WARN",
                         "Signaling", "RELAY_REGISTER_SENT", NULL, details);
}

/*
 * ============================================================================
 * INTERNAL — THREAD
 * ============================================================================
 */

static void *signal_thread_main(void *arg)
{
    bowie_engine_t *e = (bowie_engine_t *)arg;
    uint8_t         buf[BOWIE_ENGINE_SIGNAL_BUF_MAX];
    struct pollfd   pfd;

    if (e == NULL) {
        return NULL;
    }

    pfd.fd     = e->signal_fd;
    pfd.events = POLLIN;
    bowie_mtime_t next_register_ms = bowie_time_monotonic_ms() + 10000u;

    while (!e->signal_stop) {
        int rc = poll(&pfd, 1, (int)BOWIE_ENGINE_SIGNAL_POLL_MS);

        if (e->signal_relay_enabled &&
            bowie_time_monotonic_ms() >= next_register_ms) {
            signal_relay_register(e);
            next_register_ms = bowie_time_monotonic_ms() + 10000u;
        }

        if (rc < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }

        if (rc == 0) {
            continue;
        }

        if (!(pfd.revents & POLLIN)) {
            continue;
        }

        for (;;) {
            struct sockaddr_in from;
            socklen_t          from_len = sizeof(from);
            ssize_t            n;

            n = recvfrom(e->signal_fd, buf, sizeof(buf), 0,
                         (struct sockaddr *)&from, &from_len);

            if (n < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    break;
                }
                if (errno == EINTR) {
                    continue;
                }
                bowie_engine_diag("BowieSignal", "recvfrom failed: errno=%d", errno);
                break;
            }

            if (n == 0) {
                bowie_engine_diag("BowieSignal", "dropped empty UDP datagram");
                break;
            }

            if (e->signal_relay_enabled && (size_t)n >= 4u &&
                memcmp(buf, "BWSR", 4u) == 0) {
                bowie_signal_relay_packet_t relay_packet;
                if (!bowie_signal_relay_decode(buf, (size_t)n, &relay_packet) ||
                    relay_packet.type != BOWIE_SIGNAL_RELAY_FORWARD ||
                    memcmp(relay_packet.target, e->own_peer_id.bytes,
                           BOWIE_PEER_ID_LEN) != 0) {
                    bowie_diag_json_emit("WARN", "Signaling", "RELAY_PACKET_REJECTED", NULL,
                                         "{\"reason\":\"invalid_envelope_or_target\"}");
                    continue;
                }
                dispatch_frame(e, relay_packet.payload, relay_packet.payload_len,
                               &from, relay_packet.source);
            } else {
                dispatch_frame(e, buf, (size_t)n, &from, NULL);
            }
        }
    }

    return NULL;
}

/*
 * ============================================================================
 * LIFECYCLE
 * ============================================================================
 */

bowie_error_t bowie_engine_signal_open(bowie_engine_t *e,
                                       uint16_t port)
{
    struct sockaddr_in addr;
    int                fd;
    int                flags;

    if (e == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }

    if (e->cfg.signal_relay_host != NULL) {
        struct addrinfo hints;
        struct addrinfo *result = NULL;
        char service[6];
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_DGRAM;
        (void)snprintf(service, sizeof(service), "%u",
                       (unsigned)e->cfg.signal_relay_port);
        if (getaddrinfo(e->cfg.signal_relay_host, service, &hints, &result) != 0 ||
            result == NULL || result->ai_addrlen < sizeof(struct sockaddr_in)) {
            if (result != NULL) freeaddrinfo(result);
            return BOWIE_ERR_NETWORK;
        }
        memcpy(&e->signal_relay_addr, result->ai_addr,
               sizeof(e->signal_relay_addr));
        e->signal_relay_enabled = 1;
        freeaddrinfo(result);
    }

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        return BOWIE_ERR_NETWORK;
    }

    flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        close(fd);
        return BOWIE_ERR_NETWORK;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port        = htons(port);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return BOWIE_ERR_NETWORK;
    }

    {
        struct sockaddr_in actual;
        socklen_t          actual_len = sizeof(actual);

        if (getsockname(fd, (struct sockaddr *)&actual,
                        &actual_len) == 0) {
            e->signal_port = ntohs(actual.sin_port);
        } else {
            e->signal_port = port;
        }
    }

    e->signal_fd      = fd;
    e->signal_stop    = 0;
    e->signal_running = 1;

    if (pthread_create(&e->signal_thread, NULL,
                       signal_thread_main, e) != 0) {
        e->signal_running = 0;
        e->signal_stop    = 1;
        close(fd);
        e->signal_fd = -1;
        return BOWIE_ERR_INTERNAL;
    }

    signal_relay_register(e);

    if (e->cfg.signal_backend == BOWIE_SIGNAL_BACKEND_METERED) {
        bowie_metered_config_t metered_cfg;
        memset(&metered_cfg, 0, sizeof(metered_cfg));
        metered_cfg.publishable_key = e->cfg.signal_metered_api_key;
        metered_cfg.channel = e->cfg.signal_metered_channel;
        memcpy(metered_cfg.local_peer_id, e->own_peer_id.bytes, BOWIE_PEER_ID_LEN);
        metered_cfg.on_message = metered_on_message;
        metered_cfg.on_turn_server = metered_on_turn_server;
        metered_cfg.on_presence = metered_on_presence;
        metered_cfg.context = e;
        if (bowie_metered_start(&metered_cfg, &e->metered) != 0) {
            bowie_engine_signal_close(e);
            return BOWIE_ERR_NETWORK;
        }
    }

    bowie_engine_diag("BowieSignal", "UDP signaling socket bound on 0.0.0.0:%u",
                      (unsigned)e->signal_port);
    {
        char details[64];
        (void)snprintf(details, sizeof(details),
                       "{\"bind_ip\":\"0.0.0.0\",\"port\":%u}",
                       (unsigned)e->signal_port);
        bowie_diag_json_emit("INFO", "Signaling", "SIGNAL_SOCKET_BOUND", NULL, details);
    }

    return BOWIE_OK;
}

void bowie_engine_signal_close(bowie_engine_t *e)
{
    if (e == NULL) {
        return;
    }

    if (e->signal_running) {
        e->signal_stop = 1;
        pthread_join(e->signal_thread, NULL);
        e->signal_running = 0;
    }

    if (e->signal_fd >= 0) {
        close(e->signal_fd);
        e->signal_fd = -1;
    }

    if (e->metered != NULL) {
        bowie_metered_stop(e->metered);
        e->metered = NULL;
    }

    e->signal_port = 0;
}

/*
 * ============================================================================
 * SEND
 * ============================================================================
 */

bowie_error_t bowie_engine_signal_send(bowie_engine_t *e,
                                       const bowie_addr_t *to,
                                       const void *data, size_t len)
{
    uint8_t             frame[BOWIE_ENGINE_SIGNAL_BUF_MAX];
    uint8_t             relay_frame[BOWIE_ENGINE_SIGNAL_BUF_MAX + BOWIE_SIGNAL_RELAY_HEADER_LEN];
    size_t              frame_len = 0;
    size_t              wire_len;
    const uint8_t      *wire_data;
    const struct sockaddr_in *destination;
    struct sockaddr_in  sin;
    ssize_t             sent;
    bowie_error_t       rc;

    if (e == NULL || to == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }
    if (data == NULL && len > 0) {
        return BOWIE_ERR_NULL_ARG;
    }
    if (e->signal_fd < 0) {
        return BOWIE_ERR_STATE;
    }
    if (!addr_to_sockaddr_in(to, &sin)) {
        return BOWIE_ERR_INVAL;
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

    if (e->cfg.signal_backend == BOWIE_SIGNAL_BACKEND_METERED) {
        bowie_peer_id_t target;
        pthread_mutex_lock(&e->lock);
        target = !bowie_peer_id_is_zero(&e->peer.peer_id)
            ? e->peer.peer_id : e->inbound_peer_id;
        pthread_mutex_unlock(&e->lock);
        if (bowie_peer_id_is_zero(&target) || e->metered == NULL)
            return BOWIE_ERR_STATE;
        if (bowie_metered_publish(e->metered, target.bytes, data, len) != 0)
            return BOWIE_ERR_NETWORK;
        return BOWIE_OK;
    }

    wire_data = frame;
    wire_len = frame_len;
    destination = &sin;
    char peer_hex[BOWIE_PEER_ID_LEN * 2u + 1u];
    const char *peer_value = NULL;
    if (e->signal_relay_enabled) {
        bowie_peer_id_t target;
        pthread_mutex_lock(&e->lock);
        target = e->peer.peer_id;
        if (bowie_peer_id_is_zero(&target)) target = e->inbound_peer_id;
        pthread_mutex_unlock(&e->lock);
        if (bowie_peer_id_is_zero(&target) ||
            !bowie_signal_relay_encode(relay_frame, sizeof(relay_frame),
                BOWIE_SIGNAL_RELAY_DATA, e->own_peer_id.bytes, target.bytes,
                frame, frame_len, &wire_len)) return BOWIE_ERR_STATE;
        wire_data = relay_frame;
        destination = &e->signal_relay_addr;
        bowie_diag_hex(target.bytes, BOWIE_PEER_ID_LEN,
                       peer_hex, sizeof(peer_hex));
        peer_value = peer_hex;
    } else {
        pthread_mutex_lock(&e->lock);
        if (!bowie_peer_id_is_zero(&e->peer.peer_id)) {
            bowie_diag_hex(e->peer.peer_id.bytes, BOWIE_PEER_ID_LEN,
                           peer_hex, sizeof(peer_hex));
            peer_value = peer_hex;
        }
        pthread_mutex_unlock(&e->lock);
    }

    sent = sendto(e->signal_fd, wire_data, wire_len, 0,
                  (const struct sockaddr *)destination, sizeof(*destination));

    if (sent < 0) {
        bowie_engine_diag_level("BowieSignal", 1,
            "UDP send failed: destination=%u.%u.%u.%u:%u payload_bytes=%zu errno=%d",
            (unsigned)((const uint8_t *)&destination->sin_addr)[0],
            (unsigned)((const uint8_t *)&destination->sin_addr)[1],
            (unsigned)((const uint8_t *)&destination->sin_addr)[2],
            (unsigned)((const uint8_t *)&destination->sin_addr)[3],
            (unsigned)ntohs(destination->sin_port), len, errno);
        {
            char details[144];
            (void)snprintf(details, sizeof(details),
                "{\"destination_ip\":\"%u.%u.%u.%u\",\"destination_port\":%u,\"bytes\":%zu,\"errno\":%d}",
                (unsigned)((const uint8_t *)&destination->sin_addr)[0],
                (unsigned)((const uint8_t *)&destination->sin_addr)[1],
                (unsigned)((const uint8_t *)&destination->sin_addr)[2],
                (unsigned)((const uint8_t *)&destination->sin_addr)[3],
                (unsigned)ntohs(destination->sin_port), len, errno);
            bowie_diag_json_emit("ERROR", "Signaling", "SIGNAL_SEND_FAILED", peer_value, details);
        }
        return BOWIE_ERR_NETWORK;
    }

    bowie_engine_diag("BowieSignal",
        "UDP frame sent: destination=%u.%u.%u.%u:%u payload_bytes=%zu frame_bytes=%zu",
        (unsigned)((const uint8_t *)&destination->sin_addr)[0],
        (unsigned)((const uint8_t *)&destination->sin_addr)[1],
        (unsigned)((const uint8_t *)&destination->sin_addr)[2],
        (unsigned)((const uint8_t *)&destination->sin_addr)[3],
        (unsigned)ntohs(destination->sin_port), len, frame_len);
    {
        char details[320];
        (void)snprintf(details, sizeof(details),
            "{\"destination_ip\":\"%u.%u.%u.%u\",\"destination_port\":%u,\"bytes\":%zu,\"relay\":%s}",
            (unsigned)((const uint8_t *)&destination->sin_addr)[0],
            (unsigned)((const uint8_t *)&destination->sin_addr)[1],
            (unsigned)((const uint8_t *)&destination->sin_addr)[2],
            (unsigned)((const uint8_t *)&destination->sin_addr)[3],
            (unsigned)ntohs(destination->sin_port), len,
            e->signal_relay_enabled ? "true" : "false");
        bowie_diag_json_emit("INFO", "Signaling",
            bowie_diag_sdp_event((const uint8_t *)data, len), peer_value, details);
        if (bowie_diag_candidate_count((const uint8_t *)data, len) > 0u)
            bowie_diag_json_emit("DEBUG", "Signaling", "SIGNAL_CANDIDATE_SENT",
                                  peer_value, details);
    }

    return BOWIE_OK;
}

/*
 * ============================================================================
 * ADDRESS
 * ============================================================================
 */

void bowie_engine_signal_peer_addr(const bowie_engine_t *e,
                                   bowie_addr_t *out)
{
    if (e == NULL || out == NULL) {
        return;
    }

    if (!e->peer_signal_addr_valid) {
        return;
    }

    sockaddr_in_to_addr(&e->peer_signal_addr, out);
}

uint16_t bowie_engine_signal_local_port(const bowie_engine_t *e)
{
    if (e == NULL) {
        return 0;
    }
    return e->signal_port;
}

/*
 * ============================================================================
 * END OF FILE
 * ============================================================================
 */
