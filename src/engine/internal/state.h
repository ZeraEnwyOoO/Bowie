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
 * BOWIE — ENGINE STATE MACHINE (INTERNAL)
 * ============================================================================
 *
 * The allowed state transitions of the engine.
 *
 * The engine is a small state machine. Every public function
 * that can change the state goes through bowie_engine_state_set(),
 * which checks that the transition is allowed.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No subsystem state.
 *   - No side effects.
 *   - No locking. The caller must hold the engine lock.
 *
 * ----------------------------------------------------------------------------
 * Transition table
 * ----------------------------------------------------------------------------
 *
 *   from          to            who triggers
 *   ----------    ----------    ------------------------------------------
 *   STOPPED   →   STARTED       bowie_engine_start
 *   STARTED   →   CONNECTING    bowie_engine_connect / accept
 *   CONNECTING→   RUNNING       handshake + permission done
 *   CONNECTING→   STARTED       connect/accept failed or timed out
 *   RUNNING   →   STARTED       bowie_engine_disconnect
 *   any       →   STOPPED       bowie_engine_stop
 *
 * A transition to the same state is allowed and is a no-op.
 * A transition from any state to STOPPED is allowed because
 * stop must always be possible.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   "bowie/err.h"              bowie_error_t
 *   "engine/internal/engine.h" struct bowie_engine
 * ============================================================================
 */

#ifndef BOWIE_ENGINE_INTERNAL_STATE_H
#define BOWIE_ENGINE_INTERNAL_STATE_H

#include "bowie/err.h"
#include "engine/internal/engine.h"

#ifdef __cplusplus
extern "C" {
#endif

bowie_error_t bowie_engine_state_set(bowie_engine_t *e,
                                     bowie_engine_state_t new_state);

int bowie_engine_state_transition_allowed(bowie_engine_state_t from,
                                          bowie_engine_state_t to);

const char *bowie_engine_state_name_internal(bowie_engine_state_t s);

#ifdef __cplusplus
}
#endif

#endif /* BOWIE_ENGINE_INTERNAL_STATE_H */
