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
 * BOWIE — SOCKET IMPLEMENTATION
 * ============================================================================
 *
 * Portable socket primitives over the POSIX socket API.
 *
 * The implementation is a thin wrapper. It converts bowie_addr_t
 * to and from the platform's sockaddr representation, maps
 * platform errno values to bowie_error_t, and returns byte
 * counts or typed errors.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No connection management. There is no accept loop, no
 *     connect with retry, no keep-alive.
 *   - No buffering. Every read and write is a single system
 *     call.
 *   - No protocol. This is a thin wrapper over the platform
 *     socket API, not a transport.
 *   - No thread safety. A socket handle is not safe to use
 *     from more than one thread at a time.
 *   - No allocation. Every function operates on a caller-owned
 *     handle and a caller-owned buffer.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * The address conversion is the only platform-specific part.
 * Two helpers handle it:
 *
 *   - addr_to_sockaddr: writes a bowie_addr_t into a
 *     sockaddr_storage and returns the size of the storage.
 *
 *   - addr_from_sockaddr: reads a sockaddr_storage into a
 *     bowie_addr_t.
 *
 * Both helpers use the family mapping helpers
 * (family_to_platform, family_from_platform) so that the
 * mapping between bowie_af_t and the platform's AF_* values
 * lives in one place. A change to the mapping is a change to
 * two functions, not to every caller.
 *
 * The port is stored in host byte order in bowie_addr_t. The
 * conversion to and from network byte order happens in the
 * helpers, so the rest of the module never deals with byte
 * order.
 *
 * The errno mapping is local to this file. The mapping is
 * conservative: a value that is not in the list maps to
 * BOWIE_ERR_SOCKET, which is the generic platform failure.
 * A caller that needs the exact errno must read it from the
 * platform before the mapping is applied; this module does
 * not expose a saved errno.
 *
 * The send and receive functions return a long. The sign
 * distinguishes a byte count from an error code: a
 * non-negative return is a byte count, a negative return is a
 * negated bowie_error_t. This is the same shape as the POSIX
 * read and write functions, with a typed error instead of
 * errno.
 *
 * A signal interruption (EINTR) is reported as BOWIE_ERR_AGAIN,
 * which the caller can retry. The function does not retry
 * internally, because a retry in the library hides the fact
 * that the operation was interrupted.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <sys/types.h>                 ssize_t
 *   <sys/socket.h>                socket, bind, sendto, recvfrom,
 *                                 getsockname, setsockopt
 *   <netinet/in.h>                sockaddr_in, sockaddr_in6
 *   <arpa/inet.h>                 not used directly; included
 *                                 for the socket address family
 *                                 definitions on some systems
 *   <fcntl.h>                     fcntl, O_NONBLOCK
 *   <unistd.h>                    close
 *   <errno.h>                     errno
 *   <string.h>                    memset, memcpy
 *   "bowie/types.h"               bowie_addr_t, bowie_af_t
 *   "bowie/err.h"                 error codes
 *   "core/internal/sock.h"        the declarations
 * ============================================================================
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include "bowie/types.h"
#include "bowie/err.h"
#include "core/internal/sock.h"

/*
 * ============================================================================
 * ERRNO MAPPING
 * ============================================================================
 *
 * A local mapping from the platform errno to bowie_error_t. The
 * mapping is conservative: an unrecognized value maps to
 * BOWIE_ERR_SOCKET.
 */

static bowie_error_t errno_to_bowie(int e)
{
    switch (e) {
    case 0:              return BOWIE_OK;
    case EINVAL:         return BOWIE_ERR_INVAL;
    case ENOMEM:         return BOWIE_ERR_NOMEM;
    case EAGAIN:         return BOWIE_ERR_AGAIN;
    case EINTR:          return BOWIE_ERR_AGAIN;
    case ETIMEDOUT:      return BOWIE_ERR_TIMEOUT;
    case ECONNREFUSED:   return BOWIE_ERR_CONN_REFUSED;
    case ECONNRESET:     return BOWIE_ERR_CONN_RESET;
    case EHOSTUNREACH:   return BOWIE_ERR_HOST_UNREACH;
    case ENETUNREACH:    return BOWIE_ERR_NET_UNREACH;
    case EADDRINUSE:     return BOWIE_ERR_ADDR_IN_USE;
    case EADDRNOTAVAIL:  return BOWIE_ERR_ADDR_NOT_AVAIL;
    case EPIPE:          return BOWIE_ERR_BROKEN_PIPE;
    default:             return BOWIE_ERR_SOCKET;
    }
}

/*
 * ============================================================================
 * FAMILY MAPPING
 * ============================================================================
 *
 * Two functions map between the bowie_af_t enumeration and the
 * platform's AF_* values. The mapping lives here and nowhere
 * else.
 */

static int family_to_platform(bowie_af_t family)
{
    switch (family) {
    case BOWIE_AF_INET:  return AF_INET;
    case BOWIE_AF_INET6: return AF_INET6;
    default:             return -1;
    }
}

static bowie_af_t family_from_platform(int family)
{
    switch (family) {
    case AF_INET:  return BOWIE_AF_INET;
    case AF_INET6: return BOWIE_AF_INET6;
    default:       return BOWIE_AF_UNSPEC;
    }
}

/*
 * ============================================================================
 * ADDRESS CONVERSION
 * ============================================================================
 */

static int addr_to_sockaddr(const bowie_addr_t *addr,
                            struct sockaddr_storage *ss,
                            socklen_t *out_len)
{
    memset(ss, 0, sizeof(*ss));

    int pf = family_to_platform(addr->family);
    if (pf < 0) {
        return -1;
    }

    switch (addr->family) {
    case BOWIE_AF_INET: {
        struct sockaddr_in *sin = (struct sockaddr_in *)ss;
        sin->sin_family = (sa_family_t)pf;
        sin->sin_port   = htons(addr->port);
        memcpy(&sin->sin_addr, addr->addr, 4u);
        *out_len = sizeof(*sin);
        return 0;
    }
    case BOWIE_AF_INET6: {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)ss;
        sin6->sin6_family = (sa_family_t)pf;
        sin6->sin6_port   = htons(addr->port);
        memcpy(&sin6->sin6_addr, addr->addr, 16u);
        *out_len = sizeof(*sin6);
        return 0;
    }
    default:
        return -1;
    }
}

static int addr_from_sockaddr(const struct sockaddr_storage *ss,
                              bowie_addr_t *out)
{
    bowie_af_t af = family_from_platform(ss->ss_family);
    if (af == BOWIE_AF_UNSPEC) {
        return -1;
    }

    memset(out, 0, sizeof(*out));
    out->family = af;

    switch (af) {
    case BOWIE_AF_INET: {
        const struct sockaddr_in *sin =
            (const struct sockaddr_in *)ss;
        out->port = ntohs(sin->sin_port);
        memcpy(out->addr, &sin->sin_addr, 4u);
        return 0;
    }
    case BOWIE_AF_INET6: {
        const struct sockaddr_in6 *sin6 =
            (const struct sockaddr_in6 *)ss;
        out->port = ntohs(sin6->sin6_port);
        memcpy(out->addr, &sin6->sin6_addr, 16u);
        return 0;
    }
    default:
        return -1;
    }
}

/*
 * ============================================================================
 * LIFECYCLE
 * ============================================================================
 */

bowie_error_t bowie_sock_open(bowie_af_t family, int type, int *out)
{
    if (out == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }

    *out = BOWIE_SOCK_INVALID;

    int pf = family_to_platform(family);
    if (pf < 0) {
        return BOWIE_ERR_INVAL;
    }

    int st;
    switch (type) {
    case BOWIE_SOCK_STREAM: st = SOCK_STREAM; break;
    case BOWIE_SOCK_DGRAM:  st = SOCK_DGRAM;  break;
    default:                return BOWIE_ERR_INVAL;
    }

    int fd = socket(pf, st, 0);
    if (fd < 0) {
        return errno_to_bowie(errno);
    }

    *out = fd;
    return BOWIE_OK;
}

void bowie_sock_close(int fd)
{
    if (fd == BOWIE_SOCK_INVALID) {
        return;
    }
    (void)close(fd);
}

/*
 * ============================================================================
 * CONFIGURATION
 * ============================================================================
 */

bowie_error_t bowie_sock_set_reuseaddr(int fd)
{
    if (fd == BOWIE_SOCK_INVALID) {
        return BOWIE_ERR_INVAL;
    }

    int one = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR,
                   &one, sizeof(one)) < 0) {
        return errno_to_bowie(errno);
    }
    return BOWIE_OK;
}

bowie_error_t bowie_sock_set_nonblocking(int fd)
{
    if (fd == BOWIE_SOCK_INVALID) {
        return BOWIE_ERR_INVAL;
    }

    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        return errno_to_bowie(errno);
    }

    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        return errno_to_bowie(errno);
    }
    return BOWIE_OK;
}

/*
 * ============================================================================
 * BIND AND QUERY
 * ============================================================================
 */

bowie_error_t bowie_sock_bind(int fd, const bowie_addr_t *addr)
{
    if (fd == BOWIE_SOCK_INVALID) {
        return BOWIE_ERR_INVAL;
    }
    if (addr == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }

    struct sockaddr_storage ss;
    socklen_t ss_len = 0;
    if (addr_to_sockaddr(addr, &ss, &ss_len) != 0) {
        return BOWIE_ERR_INVAL;
    }

    if (bind(fd, (const struct sockaddr *)&ss, ss_len) < 0) {
        return errno_to_bowie(errno);
    }
    return BOWIE_OK;
}

bowie_error_t bowie_sock_local(int fd, bowie_addr_t *out)
{
    if (fd == BOWIE_SOCK_INVALID) {
        return BOWIE_ERR_INVAL;
    }
    if (out == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }

    struct sockaddr_storage ss;
    socklen_t ss_len = sizeof(ss);

    if (getsockname(fd, (struct sockaddr *)&ss, &ss_len) < 0) {
        return errno_to_bowie(errno);
    }

    if (addr_from_sockaddr(&ss, out) != 0) {
        return BOWIE_ERR_SOCKET;
    }
    return BOWIE_OK;
}

/*
 * ============================================================================
 * DATA TRANSFER
 * ============================================================================
 */

long bowie_sock_sendto(int fd, const bowie_addr_t *to,
                       const void *buf, size_t n)
{
    if (fd == BOWIE_SOCK_INVALID) {
        return -(long)BOWIE_ERR_INVAL;
    }
    if (to == NULL || buf == NULL) {
        return -(long)BOWIE_ERR_NULL_ARG;
    }
    if (n == 0u) {
        return 0L;
    }

    struct sockaddr_storage ss;
    socklen_t ss_len = 0;
    if (addr_to_sockaddr(to, &ss, &ss_len) != 0) {
        return -(long)BOWIE_ERR_INVAL;
    }

    ssize_t sent = sendto(fd, buf, n, 0,
                          (const struct sockaddr *)&ss, ss_len);
    if (sent < 0) {
        return -(long)errno_to_bowie(errno);
    }
    return (long)sent;
}

long bowie_sock_recvfrom(int fd, bowie_addr_t *from,
                         void *buf, size_t cap)
{
    if (fd == BOWIE_SOCK_INVALID) {
        return -(long)BOWIE_ERR_INVAL;
    }
    if (buf == NULL) {
        return -(long)BOWIE_ERR_NULL_ARG;
    }
    if (cap == 0u) {
        return 0L;
    }

    struct sockaddr_storage ss;
    socklen_t ss_len = sizeof(ss);

    ssize_t got = recvfrom(fd, buf, cap, 0,
                           (struct sockaddr *)&ss, &ss_len);
    if (got < 0) {
        return -(long)errno_to_bowie(errno);
    }

    if (from != NULL && got > 0) {
        if (addr_from_sockaddr(&ss, from) != 0) {
            /* Address family is not supported. The data is
             * still valid; report the address as unset. */
            memset(from, 0, sizeof(*from));
            from->family = BOWIE_AF_UNSPEC;
        }
    }

    return (long)got;
}

/*
 * ============================================================================
 * END OF FILE
 * ============================================================================
 */
