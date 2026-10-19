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
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "bowie/types.h"
#include "bowie/err.h"
#include "proto/framing.h"
#include "engine/internal/engine.h"
#include "engine/internal/signal.h"

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
                           const struct sockaddr_in *from)
{
    bowie_span_t payload;
    bowie_error_t rc;

    if (e == NULL || frame_buf == NULL || from == NULL) {
        return;
    }
    if (e->nat == NULL) {
        return;
    }

    rc = bowie_proto_frame_unwrap(frame_buf, frame_len, &payload);
    if (rc != BOWIE_OK) {
        return;
    }

    /*
     * Update the peer's signaling address. The lock is taken
     * for this short update and released before the NAT
     * call.
     */
    pthread_mutex_lock(&e->lock);
    if (!e->peer_signal_addr_valid) {
        e->peer_signal_addr = *from;
        e->peer_signal_addr_valid = 1;
    }
    pthread_mutex_unlock(&e->lock);

    /*
     * Hand the payload to the NAT layer.
     */
    (void)bowie_nat_signal_recv(e->nat, payload.data, payload.len);
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

    while (!e->signal_stop) {
        int rc = poll(&pfd, 1, (int)BOWIE_ENGINE_SIGNAL_POLL_MS);

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
                break;
            }

            if (n == 0) {
                break;
            }

            dispatch_frame(e, buf, (size_t)n, &from);
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
    size_t              frame_len = 0;
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

    sent = sendto(e->signal_fd, frame, frame_len, 0,
                  (struct sockaddr *)&sin, sizeof(sin));

    if (sent < 0) {
        return BOWIE_ERR_NETWORK;
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
