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
 * BOWIE — PLATFORM
 * ============================================================================
 *
 * Platform abstraction for the Bowie library.
 *
 * This header declares the platform interface that every Bowie
 * layer uses. A platform backend implements the interface. The
 * backend is selected at build time.
 *
 * This header is internal to the Bowie library. It is not part
 * of the public API and is not installed.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No runtime platform detection. The platform is chosen at
 *     build time via a preprocessor macro.
 *   - No allocation. Every function writes to caller-supplied
 *     storage or returns a value.
 *   - No I/O beyond what the platform API requires.
 *   - No policy. The interface is a thin wrapper over the
 *     platform's own API.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * The platform interface is deliberately narrow. It exposes
 * only the operations that Bowie needs and that differ between
 * platforms:
 *
 *   - Initialization. A platform may need to set up global
 *     state before any other call.
 *
 *   - Time. Monotonic and wall-clock time in milliseconds.
 *
 *   - Random. Fast and secure random bytes.
 *
 *   - Log. Writing a line to the platform's log facility.
 *
 *   - Network interface enumeration. The list of local
 *     interfaces and their addresses.
 *
 *   - Socket options. A small set of socket options that the
 *     platform API exposes differently.
 *
 * Everything else (allocation, string handling, byte order) is
 * already portable and does not need a platform backend.
 *
 * A platform backend is a set of source files under
 * src/platform/<name>/. The backend implements every function
 * in this header. The build system chooses the backend.
 *
 * The supported backends are:
 *
 *   - posix    Linux, macOS, BSD, and any other POSIX system.
 *   - linux    Linux-specific extensions (netlink, for
 *              interface enumeration).
 *   - android  Android-specific extensions (JNI, log,
 *              permissions).
 *   - windows  Windows (placeholder).
 *
 * The posix backend is the base. linux and android extend it.
 * A Linux build uses posix + linux. An Android build uses
 * posix + linux + android.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <stdint.h>                    uint8_t, uint16_t, uint32_t
 *   <stddef.h>                    size_t
 *   "bowie/types.h"               bowie_addr_t, bowie_mtime_t,
 *                                 bowie_wtime_t
 *   "bowie/err.h"                 bowie_error_t
 * ============================================================================
 */

#ifndef BOWIE_PLATFORM_PLATFORM_H
#define BOWIE_PLATFORM_PLATFORM_H

#include <stdint.h>
#include <stddef.h>

#include "bowie/types.h"
#include "bowie/err.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ============================================================================
 * PLATFORM SELECTION
 * ============================================================================
 *
 * The build system defines one of the following macros:
 *
 *   BOWIE_PLATFORM_POSIX    POSIX base (Linux, macOS, BSD)
 *   BOWIE_PLATFORM_LINUX    Linux (implies POSIX)
 *   BOWIE_PLATFORM_ANDROID  Android (implies LINUX and POSIX)
 *   BOWIE_PLATFORM_WINDOWS  Windows (placeholder)
 *
 * A build that does not define any of these is rejected at
 * compile time.
 */

#if defined(BOWIE_PLATFORM_ANDROID)
#  define BOWIE_PLATFORM_LINUX 1
#endif

#if defined(BOWIE_PLATFORM_LINUX)
#  define BOWIE_PLATFORM_POSIX 1
#endif

#if !defined(BOWIE_PLATFORM_POSIX) && \
    !defined(BOWIE_PLATFORM_WINDOWS)
#  error "No platform selected. Define one of BOWIE_PLATFORM_POSIX, BOWIE_PLATFORM_LINUX, BOWIE_PLATFORM_ANDROID, or BOWIE_PLATFORM_WINDOWS."
#endif

/*
 * ============================================================================
 * INITIALIZATION
 * ============================================================================
 */

/*
 * Initialize the platform.
 *
 * A platform that has global state to set up does so here. A
 * platform that has no global state returns BOWIE_OK without
 * doing anything.
 *
 * The function is idempotent. Calling it twice is not an
 * error.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_INTERNAL if the platform cannot be
 *   initialized.
 */
bowie_error_t bowie_platform_init(void);

/*
 * Shut down the platform.
 *
 * The function releases whatever bowie_platform_init acquired.
 * A platform that has no global state does nothing.
 *
 * The function is idempotent. Calling it twice is not an
 * error.
 */
void bowie_platform_shutdown(void);

/*
 * ============================================================================
 * TIME
 * ============================================================================
 */

/*
 * Return the monotonic clock in milliseconds.
 *
 * The value never decreases. The zero point is unspecified;
 * only differences are meaningful.
 *
 * The function does not fail.
 */
bowie_mtime_t bowie_platform_time_ms(void);

/*
 * Return the wall clock in milliseconds since the Unix epoch.
 *
 * The value follows the system's UTC time. It may move
 * backwards if the system clock is adjusted.
 *
 * The function does not fail.
 */
bowie_wtime_t bowie_platform_walltime_ms(void);

/*
 * ============================================================================
 * RANDOM
 * ============================================================================
 */

/*
 * Fill a buffer with bytes from the platform's entropy source.
 *
 * The function returns the number of bytes read, or -1 on
 * failure. A short read is possible; the caller must check the
 * return value.
 *
 * A return of 0 is not produced for a non-zero request. The
 * function either fills the buffer or reports a failure.
 */
long bowie_platform_entropy(void *buf, size_t n);

/*
 * ============================================================================
 * LOG
 * ============================================================================
 *
 * Write a line to the platform's log facility.
 *
 * On Linux and macOS this is syslog. On Android this is
 * __android_log_write. On Windows this is OutputDebugString.
 *
 * The line is NUL-terminated. The function does not prepend a
 * timestamp or a level tag; the caller supplies the complete
 * line.
 */
void bowie_platform_log_write(int level, const char *line);

/*
 * Log levels. These mirror the bowie_log_level_t values, but
 * the platform interface does not depend on bowie/config.h.
 * The caller converts.
 */
#define BOWIE_PLATFORM_LOG_NONE   0
#define BOWIE_PLATFORM_LOG_ERROR  1
#define BOWIE_PLATFORM_LOG_WARN   2
#define BOWIE_PLATFORM_LOG_INFO   3
#define BOWIE_PLATFORM_LOG_DEBUG  4
#define BOWIE_PLATFORM_LOG_TRACE  5

/*
 * ============================================================================
 * INTERFACE ENUMERATION
 * ============================================================================
 */

/*
 * The maximum number of interfaces a single enumeration
 * returns. A platform with more interfaces than this is rare;
 * a caller that needs more must enumerate in batches (which
 * this interface does not support).
 */
#define BOWIE_PLATFORM_IF_MAX 16

/*
 * The maximum length of an interface name, including the NUL
 * terminator.
 */
#define BOWIE_PLATFORM_IF_NAME_MAX 16

/*
 * A single interface entry.
 */
typedef struct bowie_platform_if {
    char        name[BOWIE_PLATFORM_IF_NAME_MAX];
    bowie_addr_t addr;          /* IPv4 or IPv6 */
    int         is_up;          /* 1 if up, 0 if down */
    int         is_loopback;    /* 1 if loopback */
    uint32_t    index;          /* interface index, if known */
} bowie_platform_if_t;

/*
 * The result of an enumeration.
 */
typedef struct bowie_platform_if_list {
    bowie_platform_if_t ifs[BOWIE_PLATFORM_IF_MAX];
    size_t              count;
} bowie_platform_if_list_t;

/*
 * Enumerate the local network interfaces.
 *
 * On success, the list is filled and the count is set.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NULL_ARG if out is NULL.
 * Returns BOWIE_ERR_NOT_IMPLEMENTED if the platform does not
 *   support enumeration.
 * Returns BOWIE_ERR_INTERNAL on a platform failure.
 */
bowie_error_t bowie_platform_if_list(bowie_platform_if_list_t *out);

/*
 * ============================================================================
 * SOCKET OPTIONS
 * ============================================================================
 */

/*
 * The platform-level socket handle type. On POSIX this is an
 * int file descriptor. On Windows it is a SOCKET.
 */
#if defined(BOWIE_PLATFORM_WINDOWS)
typedef uintptr_t bowie_platform_sock_t;
#  define BOWIE_PLATFORM_SOCK_INVALID ((bowie_platform_sock_t)~0)
#else
typedef int bowie_platform_sock_t;
#  define BOWIE_PLATFORM_SOCK_INVALID (-1)
#endif

/*
 * Set the "don't fragment" bit on a socket.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_INVAL if the handle is invalid.
 * Returns BOWIE_ERR_NOT_IMPLEMENTED if the platform does not
 *   support the option.
 * Returns BOWIE_ERR_SOCKET on a platform failure.
 */
bowie_error_t bowie_platform_sock_set_dontfrag(
    bowie_platform_sock_t fd);

/*
 * Bind a socket to a specific network interface.
 *
 * The name is the interface name (e.g. "eth0"). The name is
 * not NUL-terminated in the buffer if the interface name is
 * exactly the buffer size; the caller must ensure the name
 * fits.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NULL_ARG if name is NULL.
 * Returns BOWIE_ERR_INVAL if the handle is invalid.
 * Returns BOWIE_ERR_NOT_FOUND if the interface does not exist.
 * Returns BOWIE_ERR_NOT_IMPLEMENTED if the platform does not
 *   support the option.
 * Returns BOWIE_ERR_SOCKET on a platform failure.
 */
bowie_error_t bowie_platform_sock_bind_iface(
    bowie_platform_sock_t fd, const char *name);

/*
 * ============================================================================
 * PERMISSIONS
 * ============================================================================
 */

/*
 * Check whether the process has the permission it needs to
 * perform a network operation.
 *
 * The exact permission depends on the platform and the
 * operation. On Android the check may be a runtime permission.
 * On Linux the check may be a capability.
 *
 * Returns BOWIE_OK if the permission is granted.
 * Returns BOWIE_ERR_PERMISSION if the permission is denied.
 * Returns BOWIE_ERR_NOT_IMPLEMENTED if the platform does not
 *   need a check.
 */
bowie_error_t bowie_platform_check_permission(const char *name);

/*
 * ============================================================================
 * END OF PLATFORM
 * ============================================================================
 */

#ifdef __cplusplus
}
#endif

#endif /* BOWIE_PLATFORM_PLATFORM_H */
