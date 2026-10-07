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
 * BOWIE — TIME IMPLEMENTATION
 * ============================================================================
 *
 * Monotonic and wall-clock time access.
 *
 * The implementation is a thin wrapper over clock_gettime on
 * POSIX platforms. The result is converted to milliseconds and
 * returned as a 64-bit unsigned integer.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No formatting. Nothing here converts a timestamp to a
 *     string.
 *   - No parsing. Nothing here reads a timestamp from a string.
 *   - No sleeping. Nothing here blocks.
 *   - No timers. Nothing here schedules a callback.
 *   - No timezone handling. The wall clock is in UTC.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * The two clocks are separate functions because they answer
 * different questions:
 *
 *   - bowie_time_monotonic_ms() answers "how much time has
 *     passed?" It uses CLOCK_MONOTONIC, which is guaranteed
 *     not to jump backwards.
 *
 *   - bowie_time_wallclock_ms() answers "what time is it?" It
 *     uses CLOCK_REALTIME, which follows the system's UTC time
 *     and may be adjusted by NTP or by the operator.
 *
 * Both functions call clock_gettime and convert the timespec
 * to milliseconds:
 *
 *     ms = (uint64_t)ts.tv_sec * 1000u
 *        + (uint64_t)ts.tv_nsec / 1000000u
 *
 * The multiplication is done in 64-bit arithmetic. On a
 * 32-bit platform, tv_sec is a time_t and may be 32 bits wide;
 * the cast to uint64_t is applied before the multiplication so
 * that the result does not wrap. This is the reason for the
 * explicit cast.
 *
 * The nanosecond-to-millisecond conversion truncates. A
 * timestamp of 1.999 ms is reported as 1 ms. This is the same
 * behavior as the C11 timespec_get function and is the
 * expected behavior for a monotonic clock used for elapsed
 * time.
 *
 * Neither function can fail in a way that a caller can handle.
 * clock_gettime returns -1 only for a clock id that does not
 * exist or a timespec pointer that is NULL; both are
 * programming errors, not runtime failures. The function does
 * not check the return value, because there is no sensible
 * error to return and no sensible recovery.
 *
 * If clock_gettime is not available at link time, the build
 * fails. That is the correct behavior: a platform without a
 * working monotonic clock cannot support Bowie's timing
 * requirements.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <time.h>                      clock_gettime, timespec,
 *                                 CLOCK_MONOTONIC,
 *                                 CLOCK_REALTIME
 *   "core/internal/time.h"        the declarations
 * ============================================================================
 */

#include <time.h>

#include "core/internal/time.h"

/*
 * ============================================================================
 * MONOTONIC CLOCK
 * ============================================================================
 */

bowie_mtime_t bowie_time_monotonic_ms(void)
{
    struct timespec ts;

    /*
     * CLOCK_MONOTONIC is guaranteed not to jump backwards. It
     * is the clock to use for deadlines and timeouts.
     *
     * The return value is ignored. A failure here would mean
     * the clock id does not exist, which is a build-time
     * problem, not a runtime one.
     */
    (void)clock_gettime(CLOCK_MONOTONIC, &ts);

    return (uint64_t)ts.tv_sec * 1000u
         + (uint64_t)ts.tv_nsec / 1000000u;
}

/*
 * ============================================================================
 * WALL CLOCK
 * ============================================================================
 */

bowie_wtime_t bowie_time_wallclock_ms(void)
{
    struct timespec ts;

    /*
     * CLOCK_REALTIME follows the system's UTC time. It can
     * jump backwards or forwards when the clock is adjusted.
     * Use it for timestamps that are compared against an
     * external reference, not for elapsed time.
     */
    (void)clock_gettime(CLOCK_REALTIME, &ts);

    return (uint64_t)ts.tv_sec * 1000u
         + (uint64_t)ts.tv_nsec / 1000000u;
}

/*
 * ============================================================================
 * END OF FILE
 * ============================================================================
 */
