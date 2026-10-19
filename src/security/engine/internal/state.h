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
 * BOWIE — ENGINE: STATE (INTERNAL)
 * ============================================================================
 *
 * Internal state machine for the engine.
 *
 * This header is internal to the Bowie library. It is not part
 * of the public API and is not installed.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No public API. This header must not be included by
 *     anything outside src/engine/.
 *   - No locking. The caller must hold the engine lock before
 *     calling the transition function.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * The engine has three states: STOPPED, STARTED, RUNNING.
 * The legal transitions are:
 *
 *   STOPPED -> STARTED   (start)
 *   STARTED -> RUNNING   (connect)
 *   RUNNING -> STARTED   (disconnect)
 *   STARTED -> STOPPED   (stop)
 *   RUNNING -> STOPPED   (stop while running)
 *
 * Any other transition is a caller bug and is rejected.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   "bowie/err.h"               errors
 *   "engine/internal/engine.h"  engine handle
 * ============================================================================
 */

#ifndef BOWIE_ENGINE_INTERNAL_STATE_H
#define BOWIE_ENGINE_INTERNAL_STATE_H

#include "bowie/err.h"
#include "engine/internal/engine.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ============================================================================
 * TRANSITION
 * ============================================================================
 */

/*
 * Transition the engine to a new state.
 *
 * The function checks that the transition is legal and
 * updates the engine's state field.
 *
 * The caller must hold the engine lock.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NULL_ARG if e is NULL.
 * Returns BOWIE_ERR_STATE if the transition is not legal.
 */
bowie_error_t bowie_engine_internal_set_state(bowie_engine_t *e,
                                              bowie_engine_state_t new_state);

/*
 * ============================================================================
 * END OF INTERNAL STATE
 * ============================================================================
 */

#ifdef __cplusplus
}
#endif

#endif /* BOWIE_ENGINE_INTERNAL_STATE_H */
