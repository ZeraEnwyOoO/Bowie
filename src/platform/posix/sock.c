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
 * BOWIE — POSIX PLATFORM SOCKET OPTIONS
 * ============================================================================
 *
 * Platform-specific socket options for POSIX systems.
 *
 * The implementation provides three functions that the
 * portable socket wrapper in src/core/sock.c does not:
 *
 *   - bowie_platform_sock_set_dontfrag: set the "don't
 *     fragment" bit on a socket.
 *
 *   - bowie_platform_sock_bind_iface: bind a socket to a
 *     specific network interface.
 *
 *   - bowie_platform_check_permission: check whether the
 *     process has a permission it needs for a network
 *     operation.
 *
 * Each function has a platform-specific implementation. The
 * preprocessor selects the implementation at compile time.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No connection management. This is a set of one-shot
 *     socket options, not a transport.
 *   - No buffering.
 *   - No protocol.
 *   - No allocation.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * The "don't fragment" bit is set with IP_MTU_DISCOVER on
 * Linux and with IP_DONTFRAG on macOS and the BSDs. The two
 * options have different values and different semantics; the
 * preprocessor selects the right one.
 *
 * On Linux, IP_MTU_DISCOVER takes one of several modes. The
 * value IP_PMTUDISC_DO means "always set the DF bit and report
 * an error if the packet is too big". This is the mode Bowie
 * wants: it lets the caller discover the path MTU by sending a
 * packet that is too big and reading the error.
 *
 * On macOS and the BSDs, IP_DONTFRAG is a simple boolean.
 *
 * The interface binding is done with SO_BINDTODEVICE on
 * Linux. The option takes the interface name as a string. On
 * macOS and the BSDs, SO_BINDTODEVICE is not available; the
 * function returns BOWIE_ERR_NOT_IMPLEMENTED.
 *
 * The permission check is a no-op on a desktop POSIX system.
 * On Android it is a real check; the Android backend provides
 * a different implementation of the same function.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <sys/socket.h>                setsockopt, SO_BINDTODEVICE
 *   <netinet/in.h>                IPPROTO_IP, IP_MTU_DISCOVER,
 *                                 IP_DONTFRAG
 *   <string.h>                    strlen
 *   <errno.h>                     errno
 *   "bowie/err.h"                 error codes
 *   "platform/platform.h"         the declarations
 * ============================================================================
 */

#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <errno.h>

#include "bowie/err.h"
#include "platform/platform.h"

/*
 * ============================================================================
 * ERRNO MAPPING
 * ============================================================================
 *
 * A small local mapping from the platform errno to
 * bowie_error_t. The mapping is conservative: an unrecognized
 * value maps to BOWIE_ERR_SOCKET.
 */

static bowie_error_t errno_to_bowie(int e)
{
    switch (e) {
    case 0:              return BOWIE_OK;
    case EINVAL:         return BOWIE_ERR_INVAL;
    case ENOMEM:         return BOWIE_ERR_NOMEM;
    case ENODEV:         return BOWIE_ERR_NOT_FOUND;
    case ENXIO:          return BOWIE_ERR_NOT_FOUND;
    case EPERM:          return BOWIE_ERR_PERMISSION;
    case EACCES:         return BOWIE_ERR_PERMISSION;
    case EOPNOTSUPP:     return BOWIE_ERR_NOT_SUPPORTED;
    default:             return BOWIE_ERR_SOCKET;
    }
}

/*
 * ============================================================================
 * DON'T FRAGMENT
 * ============================================================================
 */

#if defined(BOWIE_PLATFORM_LINUX)

bowie_error_t bowie_platform_sock_set_dontfrag(
    bowie_platform_sock_t fd)
{
    if (fd == BOWIE_PLATFORM_SOCK_INVALID) {
        return BOWIE_ERR_INVAL;
    }

    /*
     * IP_PMTUDISC_DO means "always set the DF bit and report
     * an error if the packet is too big". This is the mode
     * Bowie wants: it lets the caller discover the path MTU.
     */
    int mode = IP_PMTUDISC_DO;

    if (setsockopt(fd, IPPROTO_IP, IP_MTU_DISCOVER,
                   &mode, sizeof(mode)) < 0) {
        return errno_to_bowie(errno);
    }
    return BOWIE_OK;
}

#elif defined(__APPLE__) || defined(__FreeBSD__) || \
      defined(__OpenBSD__) || defined(__NetBSD__)

bowie_error_t bowie_platform_sock_set_dontfrag(
    bowie_platform_sock_t fd)
{
    if (fd == BOWIE_PLATFORM_SOCK_INVALID) {
        return BOWIE_ERR_INVAL;
    }

    /*
     * On macOS and the BSDs, IP_DONTFRAG is a boolean. A
     * non-zero value sets the DF bit.
     */
    int on = 1;

    if (setsockopt(fd, IPPROTO_IP, IP_DONTFRAG,
                   &on, sizeof(on)) < 0) {
        return errno_to_bowie(errno);
    }
    return BOWIE_OK;
}

#else

bowie_error_t bowie_platform_sock_set_dontfrag(
    bowie_platform_sock_t fd)
{
    (void)fd;
    return BOWIE_ERR_NOT_IMPLEMENTED;
}

#endif

/*
 * ============================================================================
 * BIND TO INTERFACE
 * ============================================================================
 */

#if defined(BOWIE_PLATFORM_LINUX)

bowie_error_t bowie_platform_sock_bind_iface(
    bowie_platform_sock_t fd, const char *name)
{
    if (fd == BOWIE_PLATFORM_SOCK_INVALID) {
        return BOWIE_ERR_INVAL;
    }
    if (name == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }

    /*
     * SO_BINDTODEVICE takes the interface name as a string.
     * The length passed is the length of the name plus one,
     * to include the NUL terminator. The kernel expects the
     * terminator to be present.
     */
    size_t len = strlen(name) + 1u;

    if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE,
                   name, (socklen_t)len) < 0) {
        return errno_to_bowie(errno);
    }
    return BOWIE_OK;
}

#else

bowie_error_t bowie_platform_sock_bind_iface(
    bowie_platform_sock_t fd, const char *name)
{
    (void)fd;
    (void)name;
    return BOWIE_ERR_NOT_IMPLEMENTED;
}

#endif

/*
 * ============================================================================
 * PERMISSION CHECK
 * ============================================================================
 */

#if defined(BOWIE_PLATFORM_ANDROID)

/*
 * The Android backend provides a real implementation in
 * src/platform/android/permissions.c. This definition is a
 * placeholder that the build system never selects when the
 * Android backend is present. If it is somehow selected, it
 * returns BOWIE_ERR_NOT_IMPLEMENTED rather than a wrong
 * answer.
 */

bowie_error_t bowie_platform_check_permission(const char *name)
{
    (void)name;
    return BOWIE_ERR_NOT_IMPLEMENTED;
}

#else

bowie_error_t bowie_platform_check_permission(const char *name)
{
    /*
     * On a desktop POSIX system, the process already has the
     * permissions it needs to open a socket. The check is a
     * no-op.
     */
    (void)name;
    return BOWIE_OK;
}

#endif

/*
 * ============================================================================
 * END OF FILE
 * ============================================================================
 */
