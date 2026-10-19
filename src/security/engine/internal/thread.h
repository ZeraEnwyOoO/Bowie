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
 * BOWIE — ENGINE: THREAD (INTERNAL)
 * ============================================================================
 *
 * Internal thread management for the engine.
 *
 * This header is internal to the Bowie library. It is not part
 * of the public API and is not installed.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No I/O.
 *   - No public API. This header must not be included by
 *     anything outside src/engine/.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * The engine runs a single background thread that drains the
 * event queue. The thread is started with bowie_engine_thread_start()
 * and stopped with bowie_engine_thread_stop(). The thread
 * functions are declared in this header and implemented in
 * thread.c.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <pthread.h>                 pthread_t
 *   "bowie/err.h"               errors
 *   "engine/internal/engine.h"  engine handle
 * ============================================================================
 */

#ifndef BOWIE_ENGINE_INTERNAL_THREAD_H
#define BOWIE_ENGINE_INTERNAL_THREAD_H

#include <pthread.h>

#include "bowie/err.h"
#include "engine/internal/engine.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ============================================================================
 * API
 * ============================================================================
 */

/*
 * Start the engine's background thread.
 *
 * The thread drains the event queue and calls back into the
 * engine for each event. The engine must be in the STARTED or
 * RUNNING state.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NULL_ARG if e is NULL.
 * Returns BOWIE_ERR_STATE if the thread is already running.
 * Returns BOWIE_ERR_INTERNAL if the thread could not be
 *   created.
 */
bowie_error_t bowie_engine_thread_start(bowie_engine_t *e);

/*
 * Stop the engine's background thread.
 *
 * The thread is asked to exit and the call waits for it to
 * do so.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NULL_ARG if e is NULL.
 * Returns BOWIE_ERR_NOT_STARTED if the thread is not running.
 */
bowie_error_t bowie_engine_thread_stop(bowie_engine_t *e);

/*
 * ============================================================================
 * END OF INTERNAL THREAD
 * ============================================================================
 */

#ifdef __cplusplus
}
#endif

#endif /* BOWIE_ENGINE_INTERNAL_THREAD_H */
