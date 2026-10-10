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
 * BOWIE — POSIX PLATFORM ENTROPY
 * ============================================================================
 *
 * Platform entropy source for POSIX systems.
 *
 * The implementation uses the platform's own entropy source.
 * On Linux this is getrandom(2). On the BSDs and macOS this is
 * getentropy(2) or arc4random_buf(3). The choice is made at
 * compile time by the preprocessor.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No pseudo-random generator. This file provides raw
 *     entropy from the platform. A caller that needs a fast,
 *     seedable generator must build one on top.
 *   - No caching. Every call reads fresh entropy.
 *   - No user-space fallback. If the platform has no entropy
 *     source, the function reports failure; it does not fall
 *     back to a weaker source.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * The function returns the number of bytes read, or -1 on
 * failure. A short read is possible: the platform may return
 * fewer bytes than requested. The caller must check the return
 * value and, if it needs more, call again.
 *
 * On Linux, getrandom(2) is used. It is the preferred interface
 * since kernel 3.17. It reads from the kernel's entropy pool
 * and blocks until the pool is initialized (unless the
 * GRND_NONBLOCK flag is set, which this file does not set).
 *
 * A signal interruption (EINTR) is retried. The function does
 * not return a partial result for an interruption; it retries
 * the call.
 *
 * A return of 0 is not produced by this function for a
 * non-zero request. A return of -1 means the platform refused
 * the request; a caller must treat it as a hard failure.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <errno.h>                     errno
 *   <sys/types.h>                 ssize_t
 *   "platform/platform.h"         the declarations
 *
 * On Linux:
 *   <sys/random.h>                getrandom
 *
 * On macOS and the BSDs:
 *   <stdlib.h>                    arc4random_buf
 * ============================================================================
 */

#include <errno.h>
#include <sys/types.h>

#include "platform/platform.h"

/*
 * ============================================================================
 * LINUX
 * ============================================================================
 */

#if defined(BOWIE_PLATFORM_LINUX)

#include <sys/random.h>

long bowie_platform_entropy(void *buf, size_t n)
{
    if (buf == NULL && n > 0u) {
        return -1;
    }
    if (n == 0u) {
        return 0;
    }

    /*
     * getrandom(2) can be interrupted by a signal. A short
     * read is retried with the remaining buffer. A permanent
     * failure is reported.
     *
     * The call does not use GRND_NONBLOCK. If the kernel
     * entropy pool is not yet initialized, the call blocks
     * until it is. This is the correct behavior for a
     * security-sensitive source.
     */
    uint8_t *p = (uint8_t *)buf;
    size_t   remaining = n;

    while (remaining > 0u) {
        ssize_t got = getrandom(p, remaining, 0);
        if (got < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (got == 0) {
            return -1;
        }
        p         += (size_t)got;
        remaining -= (size_t)got;
    }

    return (long)n;
}

/*
 * ============================================================================
 * MACOS AND THE BSDs
 * ============================================================================
 */

#elif defined(__APPLE__) || defined(__FreeBSD__) || \
      defined(__OpenBSD__) || defined(__NetBSD__)

#include <stdlib.h>

long bowie_platform_entropy(void *buf, size_t n)
{
    if (buf == NULL && n > 0u) {
        return -1;
    }
    if (n == 0u) {
        return 0;
    }

    /*
     * arc4random_buf is available on macOS and the BSDs. It
     * is a CSPRNG seeded from the platform entropy source.
     * It does not fail.
     */
    arc4random_buf(buf, n);
    return (long)n;
}

/*
 * ============================================================================
 * NO ENTROPY SOURCE
 * ============================================================================
 */

#else

long bowie_platform_entropy(void *buf, size_t n)
{
    (void)buf;
    (void)n;
    return -1;
}

#endif

/*
 * ============================================================================
 * END OF FILE
 * ============================================================================
 */
