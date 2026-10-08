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
 * BOWIE — SOCKET (INTERNAL)
 * ============================================================================
 *
 * Portable socket primitives for the Bowie library.
 *
 * This header is internal to the Bowie library. It is not part
 * of the public API and is not installed.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No connection management. There is no accept loop, no
 *     connect with retry, no keep-alive. A caller that wants
 *     a connection uses connect() once and handles the result.
 *   - No buffering. Every read and write is a single system
 *     call. A caller that wants a buffered stream must build
 *     one on top.
 *   - No protocol. This is a thin wrapper over the platform
 *     socket API, not a transport.
 *   - No thread safety. A socket handle is not safe to use
 *     from more than one thread at a time. A caller that
 *     shares a handle between threads must serialize access.
 *   - No allocation. Every function operates on a caller-owned
 *     handle and a caller-owned buffer.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * A socket is represented by an int file descriptor. The value
 * -1 is reserved and means "invalid handle". A handle that is
 * not -1 is a file descriptor that the platform socket API
 * recognizes.
 *
 * Every function that takes a handle checks for -1 and returns
 * an error rather than calling the platform with a bad handle.
 * This is the same contract as the platform API, but with a
 * single, named error (BOWIE_ERR_INVAL) instead of a platform
 * errno.
 *
 * The functions are grouped by purpose:
 *
 *   - Creation and destruction: bowie_sock_open, bowie_sock_close.
 *   - Configuration: bowie_sock_set_reuseaddr, bowie_sock_set_nonblocking.
 *   - Binding and querying: bowie_sock_bind, bowie_sock_local.
 *   - Data transfer: bowie_sock_sendto, bowie_sock_recvfrom.
 *
 * The address type is bowie_addr_t, defined in bowie/types.h.
 * A bowie_addr_t is a family, an address payload, and a port
 * in host byte order. The socket functions convert to and from
 * the platform's sockaddr representation at the boundary.
 *
 * The address payload is large enough for IPv6, so one type
 * covers both families. The family tag selects the meaningful
 * prefix: for BOWIE_AF_INET, the first four bytes; for
 * BOWIE_AF_INET6, all sixteen.
 *
 * The sendto and recvfrom functions return the number of bytes
 * transferred, or a negative bowie_error_t on failure. The
 * sign distinguishes the two: a non-negative return is a byte
 * count, a negative return is an error code. This is the same
 * shape as the POSIX read and write functions, with a typed
 * error instead of errno.
 *
 * The recvfrom function writes the sender's address through an
 * out pointer, if the pointer is non-NULL. A caller that does
 * not care about the sender passes NULL.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <stdint.h>                    uint16_t
 *   <stddef.h>                    size_t
 *   "bowie/types.h"               bowie_addr_t, bowie_af_t
 *   "bowie/err.h"                 bowie_error_t
 * ============================================================================
 */

#ifndef BOWIE_CORE_INTERNAL_SOCK_H
#define BOWIE_CORE_INTERNAL_SOCK_H

#include <stdint.h>
#include <stddef.h>

#include "bowie/types.h"
#include "bowie/err.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ============================================================================
 * HANDLE
 * ============================================================================
 *
 * A socket handle is an int file descriptor. The value -1 is
 * reserved and means "invalid handle". A valid handle is any
 * non-negative value.
 */

#define BOWIE_SOCK_INVALID (-1)

/*
 * ============================================================================
 * LIFECYCLE
 * ============================================================================
 */

/*
 * Create a socket.
 *
 * The family is one of BOWIE_AF_INET or BOWIE_AF_INET6. The
 * type is one of BOWIE_SOCK_STREAM (TCP) or BOWIE_SOCK_DGRAM
 * (UDP). The type values are defined below.
 *
 * On success, the new file descriptor is written through out.
 * On failure, *out is set to BOWIE_SOCK_INVALID.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NULL_ARG if out is NULL.
 * Returns BOWIE_ERR_INVAL if the family or the type is not
 *   supported.
 * Returns BOWIE_ERR_NOMEM if the platform refuses the request
 *   for lack of memory.
 * Returns BOWIE_ERR_SOCKET for any other platform failure.
 */
bowie_error_t bowie_sock_open(bowie_af_t family, int type, int *out);

/*
 * Close a socket.
 *
 * Closing an invalid handle is a no-op.
 */
void bowie_sock_close(int fd);

/*
 * ============================================================================
 * SOCKET TYPES
 * ============================================================================
 */

#define BOWIE_SOCK_STREAM 1
#define BOWIE_SOCK_DGRAM  2

/*
 * ============================================================================
 * CONFIGURATION
 * ============================================================================
 */

/*
 * Enable SO_REUSEADDR on a socket.
 *
 * Returns BOWIE_OK on success, BOWIE_ERR_INVAL if the handle
 * is invalid, or BOWIE_ERR_SOCKET on a platform failure.
 */
bowie_error_t bowie_sock_set_reuseaddr(int fd);

/*
 * Set a socket to non-blocking mode.
 *
 * Returns BOWIE_OK on success, BOWIE_ERR_INVAL if the handle
 * is invalid, or BOWIE_ERR_SOCKET on a platform failure.
 */
bowie_error_t bowie_sock_set_nonblocking(int fd);

/*
 * ============================================================================
 * BIND AND QUERY
 * ============================================================================
 */

/*
 * Bind a socket to a local address.
 *
 * The address must have a valid family. The port is in host
 * byte order. A port of 0 means "let the platform choose".
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NULL_ARG if addr is NULL.
 * Returns BOWIE_ERR_INVAL if the handle is invalid or the
 *   address family is not supported.
 * Returns BOWIE_ERR_ADDR_IN_USE if the address is already in
 *   use.
 * Returns BOWIE_ERR_SOCKET for any other platform failure.
 */
bowie_error_t bowie_sock_bind(int fd, const bowie_addr_t *addr);

/*
 * Query the local address a socket is bound to.
 *
 * On success, the address is written through out. The port is
 * in host byte order.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NULL_ARG if out is NULL.
 * Returns BOWIE_ERR_INVAL if the handle is invalid.
 * Returns BOWIE_ERR_SOCKET on a platform failure.
 */
bowie_error_t bowie_sock_local(int fd, bowie_addr_t *out);

/*
 * ============================================================================
 * DATA TRANSFER
 * ============================================================================
 */

/*
 * Send n bytes to a peer.
 *
 * The return value is the number of bytes sent on success, or
 * a negative bowie_error_t on failure. A non-negative return
 * is a byte count; a negative return is an error code.
 *
 * A return of 0 is not produced by this function; a send of
 * zero bytes is not meaningful and is treated as a no-op by
 * the platform.
 */
long bowie_sock_sendto(int fd, const bowie_addr_t *to,
                       const void *buf, size_t n);

/*
 * Receive up to cap bytes from a peer.
 *
 * The sender's address is written through from, if from is
 * non-NULL. The number of bytes received is returned.
 *
 * The return value is the number of bytes received on success,
 * or a negative bowie_error_t on failure. A return of 0 is a
 * valid result and means "no bytes available".
 */
long bowie_sock_recvfrom(int fd, bowie_addr_t *from,
                         void *buf, size_t cap);

/*
 * ============================================================================
 * END OF INTERNAL SOCKET
 * ============================================================================
 */

#ifdef __cplusplus
}
#endif

#endif /* BOWIE_CORE_INTERNAL_SOCK_H */
