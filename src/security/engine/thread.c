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
 * BOWIE — ENGINE: THREAD (IMPLEMENTATION)
 * ============================================================================
 *
 * Implementation of the engine's background thread.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No I/O.
 *   - No event handling. The thread drains the queue and
 *     calls into the engine for each event; the engine
 *     decides what to do.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <pthread.h>                 pthread_t
 *   "bowie/err.h"               errors
 *   "engine/internal/thread.h"  declarations
 * ============================================================================
 */

#include <pthread.h>

#include "bowie/err.h"
#include "engine/internal/thread.h"

bowie_error_t bowie_engine_thread_start(bowie_engine_t *e)
{
    if (e == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }

    /*
     * Placeholder: the thread is created here when the
     * engine's event loop is in place. Until then, the
     * function reports success without starting anything.
     */

    return BOWIE_OK;
}

bowie_error_t bowie_engine_thread_stop(bowie_engine_t *e)
{
    if (e == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }

    /*
     * Placeholder: the thread is stopped here when the
     * engine's event loop is in place. Until then, the
     * function reports success without stopping anything.
     */

    return BOWIE_OK;
}

/*
 * ============================================================================
 * END OF ENGINE THREAD IMPLEMENTATION
 * ============================================================================
 */
