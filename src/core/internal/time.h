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
 * BOWIE — TIME (INTERNAL)
 * ============================================================================
 *
 * Monotonic and wall-clock time access for the Bowie library.
 *
 * This header is internal to the Bowie library. It is not part
 * of the public API and is not installed.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No formatting. Nothing here converts a timestamp to a
 *     string. A caller that needs a human-readable time must
 *     format it itself.
 *   - No parsing. Nothing here reads a timestamp from a string.
 *   - No sleeping. Nothing here blocks. A caller that needs to
 *     wait must do it itself.
 *   - No timers. Nothing here schedules a callback. A caller
 *     that needs a deadline must compute it from the monotonic
 *     clock.
 *   - No timezone handling. The wall clock is in UTC.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * Two clocks are exposed, and they are not interchangeable:
 *
 *   - The monotonic clock never goes backwards. It is used for
 *     measuring elapsed time, for deadlines, and for timeouts.
 *     Its zero point is unspecified; only differences are
 *     meaningful.
 *
 *   - The wall clock follows the system's UTC time. It can jump
 *     backwards or forwards, for example when NTP adjusts the
 *     clock. It is used for timestamps that are compared
 *     against an external reference, such as the issued_at and
 *     expires_at fields of a grant.
 *
 * A caller that needs to compare two events in time must use
 * the monotonic clock. A caller that needs to record when an
 * event happened in the real world must use the wall clock. A
 * caller that needs both reads both.
 *
 * Both clocks return milliseconds as a 64-bit unsigned integer.
 * A 64-bit millisecond value is enough for roughly 584 million
 * years, so there is no overflow concern for any reasonable
 * use.
 *
 * The wall-clock value is milliseconds since the Unix epoch
 * (1970-01-01T00:00:00 UTC). A wall-clock value before the
 * epoch cannot be represented; the function does not produce
 * one in practice.
 *
 * The monotonic clock uses CLOCK_MONOTONIC on POSIX platforms.
 * On a platform where CLOCK_MONOTONIC is not available, the
 * implementation falls back to a different monotonic source or
 * fails to build. This header does not expose a platform
 * abstraction; the platform layer, if any is needed, is a
 * separate concern.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <stdint.h>                    uint64_t
 *   "bowie/types.h"               bowie_mtime_t, bowie_wtime_t
 * ============================================================================
 */

#ifndef BOWIE_CORE_INTERNAL_TIME_H
#define BOWIE_CORE_INTERNAL_TIME_H

#include <stdint.h>

#include "bowie/types.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ============================================================================
 * MONOTONIC CLOCK
 * ============================================================================
 *
 * Return the monotonic clock in milliseconds.
 *
 * The value never decreases. Two calls in the same process are
 * ordered by their return values: a later call returns a value
 * greater than or equal to an earlier call.
 *
 * The zero point is unspecified. Only differences between two
 * values are meaningful; the absolute value is not.
 *
 * This function does not fail. It never returns a negative
 * value (the return type is unsigned).
 */
bowie_mtime_t bowie_time_monotonic_ms(void);

/*
 * ============================================================================
 * WALL CLOCK
 * ============================================================================
 *
 * Return the wall clock in milliseconds since the Unix epoch.
 *
 * The value follows the system's UTC time. It may move
 * backwards or forwards if the system clock is adjusted; a
 * caller that needs a strict ordering must use the monotonic
 * clock instead.
 *
 * This function does not fail. It never returns a negative
 * value (the return type is unsigned).
 */
bowie_wtime_t bowie_time_wallclock_ms(void);

/*
 * ============================================================================
 * END OF INTERNAL TIME
 * ============================================================================
 */

#ifdef __cplusplus
}
#endif

#endif /* BOWIE_CORE_INTERNAL_TIME_H */
