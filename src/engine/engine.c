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
 * BOWIE — ENGINE STATE MACHINE (IMPLEMENTATION)
 * ============================================================================
 *
 * Implementation of the engine state machine declared in
 * engine/internal/state.h.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No subsystem work. The caller of bowie_engine_state_set()
 *     is the one that starts or stops the DHT, NAT, and
 *     gateway. This file only updates e->state.
 *   - No logging. A failed transition returns an error code;
 *     the caller decides whether to log it.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * The transition table is a switch on the "from" state. Each
 * case lists the allowed "to" states. The function is pure;
 * it does not touch the engine.
 *
 * "any → STOPPED" is special-cased before the switch. Stop
 * must always be possible; a state that refused to stop
 * would be a bug.
 *
 * "same → same" is special-cased too. Setting the state to
 * its current value is a no-op, not an error. This makes
 * bowie_engine_state_set() safe to call from a context that
 * may already have set the state (for example, the connect
 * path that fails after a partial transition).
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   "bowie/err.h"                bowie_error_t and codes
 *   "engine/engine.h"            bowie_engine_state_t
 *   "engine/internal/engine.h"   struct bowie_engine
 *   "engine/internal/state.h"    declarations
 * ============================================================================
 */

#include "bowie/err.h"
#include "engine/engine.h"
#include "engine/internal/engine.h"
#include "engine/internal/state.h"

/*
 * ============================================================================
 * TRANSITION TABLE
 * ============================================================================
 */

int bowie_engine_state_transition_allowed(bowie_engine_state_t from,
                                          bowie_engine_state_t to)
{
    if (from == to) {
        return 1;
    }

    if (to == BOWIE_ENGINE_STOPPED) {
        return 1;
    }

    switch (from) {
    case BOWIE_ENGINE_STOPPED:
        return (to == BOWIE_ENGINE_STARTED) ? 1 : 0;

    case BOWIE_ENGINE_STARTED:
        return (to == BOWIE_ENGINE_CONNECTING ||
                to == BOWIE_ENGINE_STOPPED) ? 1 : 0;

    case BOWIE_ENGINE_CONNECTING:
        return (to == BOWIE_ENGINE_RUNNING ||
                to == BOWIE_ENGINE_STARTED ||
                to == BOWIE_ENGINE_STOPPED) ? 1 : 0;

    case BOWIE_ENGINE_RUNNING:
        return (to == BOWIE_ENGINE_STARTED ||
                to == BOWIE_ENGINE_STOPPED) ? 1 : 0;

    default:
        return 0;
    }
}

/*
 * ============================================================================
 * TRANSITION
 * ============================================================================
 */

bowie_error_t bowie_engine_state_set(bowie_engine_t *e,
                                     bowie_engine_state_t new_state)
{
    if (e == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }

    if (!bowie_engine_state_transition_allowed(e->state, new_state)) {
        return BOWIE_ERR_STATE_TRANSITION;
    }

    e->state = new_state;
    return BOWIE_OK;
}

/*
 * ============================================================================
 * NAME
 * ============================================================================
 */

const char *bowie_engine_state_name_internal(bowie_engine_state_t s)
{
    switch (s) {
    case BOWIE_ENGINE_STOPPED:
        return "STOPPED";
    case BOWIE_ENGINE_STARTED:
        return "STARTED";
    case BOWIE_ENGINE_CONNECTING:
        return "CONNECTING";
    case BOWIE_ENGINE_RUNNING:
        return "RUNNING";
    default:
        return "UNKNOWN";
    }
}

/*
 * ============================================================================
 * END OF FILE
 * ============================================================================
 */
