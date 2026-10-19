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
 * BOWIE — ENGINE: STATE (IMPLEMENTATION)
 * ============================================================================
 *
 * Implementation of the engine state machine.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No DHT or NAT. The state machine only tracks the
 *     engine's own state.
 *   - No I/O.
 *   - No locking. The caller must hold the engine lock.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * A transition to the same state is a no-op.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   "bowie/err.h"               errors
 *   "engine/internal/state.h"   declarations
 * ============================================================================
 */

#include "bowie/err.h"
#include "engine/internal/state.h"

bowie_error_t bowie_engine_internal_set_state(bowie_engine_t *e,
                                              bowie_engine_state_t new_state)
{
    if (e == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }

    if (e->state == new_state) {
        return BOWIE_OK;
    }

    switch (e->state) {
    case BOWIE_ENGINE_STOPPED:
        if (new_state == BOWIE_ENGINE_STARTED) {
            e->state = new_state;
            return BOWIE_OK;
        }
        return BOWIE_ERR_STATE;

    case BOWIE_ENGINE_STARTED:
        if (new_state == BOWIE_ENGINE_RUNNING ||
            new_state == BOWIE_ENGINE_STOPPED) {
            e->state = new_state;
            return BOWIE_OK;
        }
        return BOWIE_ERR_STATE;

    case BOWIE_ENGINE_RUNNING:
        if (new_state == BOWIE_ENGINE_STARTED ||
            new_state == BOWIE_ENGINE_STOPPED) {
            e->state = new_state;
            return BOWIE_OK;
        }
        return BOWIE_ERR_STATE;

    default:
        return BOWIE_ERR_STATE;
    }
}

/*
 * ============================================================================
 * END OF ENGINE STATE IMPLEMENTATION
 * ============================================================================
 */
