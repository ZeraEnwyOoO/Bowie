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
 * BOWIE — POSIX PLATFORM TIME
 * ============================================================================
 *
 * Monotonic and wall-clock time for POSIX systems.
 *
 * The implementation is a thin wrapper over clock_gettime. The
 * result is converted to milliseconds and returned as a 64-bit
 * unsigned integer.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No formatting. Nothing here converts a timestamp to a
 *     string.
 *   - No parsing.
 *   - No sleeping. Nothing here blocks.
 *   - No timers.
 *   - No timezone handling. The wall clock is in UTC.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * The platform interface exposes two clocks:
 *
 *   - bowie_platform_time_ms() answers "how much time has
 *     passed?" It uses CLOCK_MONOTONIC.
 *
 *   - bowie_platform_walltime_ms() answers "what time is it?"
 *     It uses CLOCK_REALTIME.
 *
 * The platform interface does not promise that the two clocks
 * are related. The monotonic clock's zero point is
 * unspecified. The wall clock's zero point is the Unix epoch.
 *
 * The timespec is initialized to zero before the call. If
 * clock_gettime fails, the function returns zero instead of
 * reading an uninitialized value. Zero is a defined result;
 * an uninitialized read is not.
 *
 * The multiplication is done in 64-bit arithmetic. On a
 * 32-bit platform, tv_sec is a time_t and may be 32 bits wide;
 * the cast to uint64_t is applied before the multiplication so
 * that the result does not wrap.
 *
 * The nanosecond-to-millisecond conversion truncates. A
 * timestamp of 1.999 ms is reported as 1 ms. This is the
 * expected behavior for a monotonic clock used for elapsed
 * time.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <time.h>                      clock_gettime, timespec,
 *                                 CLOCK_MONOTONIC,
 *                                 CLOCK_REALTIME
 *   <stdint.h>                    uint64_t
 *   "platform/platform.h"         the declarations
 * ============================================================================
 */

#include <time.h>
#include <stdint.h>

#include "platform/platform.h"

/*
 * ============================================================================
 * MONOTONIC CLOCK
 * ============================================================================
 */

bowie_mtime_t bowie_platform_time_ms(void)
{
    /*
     * The timespec is initialized to zero before the call.
     * If clock_gettime fails, the function returns zero
     * instead of reading an uninitialized value.
     *
     * CLOCK_MONOTONIC is guaranteed not to jump backwards.
     * It is the clock to use for deadlines and timeouts.
     */
    struct timespec ts = { 0, 0 };

    (void)clock_gettime(CLOCK_MONOTONIC, &ts);

    return (uint64_t)ts.tv_sec * 1000u
         + (uint64_t)ts.tv_nsec / 1000000u;
}

/*
 * ============================================================================
 * WALL CLOCK
 * ============================================================================
 */

bowie_wtime_t bowie_platform_walltime_ms(void)
{
    /*
     * The timespec is initialized to zero before the call.
     * See the note in the monotonic function.
     *
     * CLOCK_REALTIME follows the system's UTC time. It can
     * jump backwards or forwards when the clock is adjusted.
     * Use it for timestamps that are compared against an
     * external reference, not for elapsed time.
     */
    struct timespec ts = { 0, 0 };

    (void)clock_gettime(CLOCK_REALTIME, &ts);

    return (uint64_t)ts.tv_sec * 1000u
         + (uint64_t)ts.tv_nsec / 1000000u;
}

/*
 * ============================================================================
 * END OF FILE
 * ============================================================================
 */
