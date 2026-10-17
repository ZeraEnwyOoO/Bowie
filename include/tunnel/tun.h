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
 * BOWIE — TUNNEL TUN DEVICE
 * ============================================================================
 *
 * Virtual network interface (TUN) management for the Bowie tunnel.
 *
 * A TUN device is a kernel feature that allows a userspace
 * program to read and write raw IP packets. Bowie uses it to
 * intercept traffic on Peer B and route it through the tunnel
 * to Peer A.
 *
 * This header declares the platform-independent interface for
 * opening, reading from, writing to, and closing a TUN device.
 * The implementation lives in a platform-specific source file
 * (e.g., src/tunnel/tun_linux.c).
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No routing. Opening a TUN device does not automatically
 *     route traffic into it. The caller (or the Gateway layer)
 *     must configure the system routing table.
 *   - No NAT. The TUN device only handles packet I/O; network
 *     address translation is a Gateway concern.
 *   - No encryption. Packets read from the TUN device are raw.
 *     Encryption is applied by the Session layer before they
 *     are sent over the NAT connection.
 *   - No platform-specific logic. The struct is opaque, and
 *     the functions dispatch to the platform backend.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * The TUN handle is opaque. The caller owns it, never sees its
 * layout, and frees it with bowie_tun_close().
 *
 * Reading from and writing to a TUN device is synchronous and
 * blocking by default. The caller can use the file descriptor
 * returned by bowie_tun_fd() to poll or select on the device
 * if it needs non-blocking I/O.
 *
 * The read and write functions are zero-copy: they write
 * directly into the caller's buffer. There is no intermediate
 * buffer inside the TUN implementation.
 *
 * A TUN device is a scarce resource: it requires elevated
 * privileges (CAP_NET_ADMIN on Linux) to create. The caller
 * must handle permission errors gracefully and inform the user.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <stddef.h>          size_t
 *   "bowie/types.h"     bowie_tun_t
 *   "bowie/err.h"       bowie_error_t
 * ============================================================================
 */

#ifndef BOWIE_TUNNEL_TUN_H
#define BOWIE_TUNNEL_TUN_H

#include <stddef.h>

#include "bowie/types.h"
#include "bowie/err.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ============================================================================
 * LIFECYCLE
 * ============================================================================
 */

/*
 * Open and configure a TUN device.
 *
 * The name parameter is a hint. If the name is NULL or empty,
 * the operating system assigns a name (e.g., "tun0"). If the
 * name is provided, the function tries to use it; if the
 * device already exists or the name is invalid, the call
 * fails.
 *
 * The mtu parameter sets the Maximum Transmission Unit of the
 * device. Passing zero uses the tunnel default
 * (BOWIE_TUN_MTU_TUNNEL).
 *
 * On success, *out points to the new TUN handle.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NULL_ARG if out is NULL.
 * Returns BOWIE_ERR_INVAL if the MTU is invalid.
 * Returns BOWIE_ERR_PERMISSION if the process lacks the
 * required privileges.
 * Returns BOWIE_ERR_SOCKET if the device could not be opened.
 * Returns BOWIE_ERR_NOT_IMPLEMENTED if the platform backend is
 * missing.
 */
bowie_error_t bowie_tun_open(bowie_tun_t **out,
                             const char *name,
                             size_t mtu);

/*
 * Close a TUN device.
 *
 * This releases the file descriptor and destroys the
 * interface. Any packets in flight are dropped.
 *
 * Passing NULL is a no-op.
 */
void bowie_tun_close(bowie_tun_t *tun);

/*
 * Return the underlying file descriptor of the TUN device.
 *
 * This is used for poll(), select(), or epoll() when the
 * caller wants to integrate the TUN device into an event
 * loop.
 *
 * Returns -1 if the handle is NULL or closed.
 */
int bowie_tun_fd(const bowie_tun_t *tun);

/*
 * ============================================================================
 * I/O
 * ============================================================================
 */

/*
 * Read one IP packet from the TUN device into the caller's
 * buffer.
 *
 * This function blocks until a packet is available. The
 * caller may use bowie_tun_fd() and poll() if it needs a
 * timeout or non-blocking behavior.
 *
 * Returns the number of bytes read (the packet length).
 * Returns BOWIE_ERR_NULL_ARG if tun or buf is NULL.
 * Returns BOWIE_ERR_TOO_SMALL if cap is smaller than the
 * largest possible packet.
 * Returns BOWIE_ERR_NETWORK if the read fails.
 */
long bowie_tun_read(bowie_tun_t *tun, void *buf, size_t cap);

/*
 * Write one IP packet to the TUN device.
 *
 * The packet is injected into the kernel's network stack as
 * if it had arrived from a physical interface. The kernel
 * will route it according to the system routing table.
 *
 * The buffer is not modified.
 *
 * Returns the number of bytes written.
 * Returns BOWIE_ERR_NULL_ARG if tun or buf is NULL.
 * Returns BOWIE_ERR_INVAL if len is zero.
 * Returns BOWIE_ERR_TOO_LARGE if len exceeds the device MTU.
 * Returns BOWIE_ERR_NETWORK if the write fails.
 */
long bowie_tun_write(bowie_tun_t *tun, const void *buf, size_t len);

/*
 * ============================================================================
 * END OF TUNNEL TUN
 * ============================================================================
 */

#ifdef __cplusplus
}
#endif

#endif /* BOWIE_TUNNEL_TUN_H */
