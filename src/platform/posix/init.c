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
 * BOWIE — POSIX PLATFORM INITIALIZATION
 * ============================================================================
 *
 * Platform initialization for POSIX systems.
 *
 * A POSIX platform has no global state that needs to be set up
 * at startup. The two functions here are no-ops. They exist so
 * that the platform interface is complete and so that a
 * caller can call bowie_platform_init() unconditionally,
 * without knowing which platform it was built for.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No signal handling. A caller that wants signal handling
 *     must install its own.
 *   - No locale setup. The C library's default locale is used.
 *   - No file descriptor limit change. The process limit is
 *     whatever the parent set.
 *   - No daemonization. A caller that wants to run as a daemon
 *     must do it itself.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * Both functions are idempotent. Calling init twice is not an
 * error. Calling shutdown twice is not an error. Calling
 * shutdown without a preceding init is not an error.
 *
 * This is the right behavior for a platform with no state: a
 * caller that does not know whether the platform was already
 * initialized can call init unconditionally, and a caller
 * that wants to be safe on any exit path can call shutdown
 * unconditionally.
 *
 * The functions are declared in src/platform/platform.h. The
 * header declares them for every platform; this file provides
 * the POSIX implementation.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   "platform/platform.h"        the declarations
 * ============================================================================
 */

#include "platform/platform.h"

/*
 * ============================================================================
 * INITIALIZATION
 * ============================================================================
 */

bowie_error_t bowie_platform_init(void)
{
    /*
     * A POSIX platform has no global state to set up. The
     * function returns BOWIE_OK so that a caller can call it
     * unconditionally.
     */
    return BOWIE_OK;
}

void bowie_platform_shutdown(void)
{
    /*
     * A POSIX platform has no global state to tear down. The
     * function is a no-op.
     */
}

/*
 * ============================================================================
 * END OF FILE
 * ============================================================================
 */
