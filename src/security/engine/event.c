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
 * BOWIE — ENGINE: EVENT (IMPLEMENTATION)
 * ============================================================================
 *
 * Implementation of the engine event queue.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No I/O.
 *   - No threading.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   "bowie/err.h"               errors
 *   "engine/internal/event.h"   declarations
 * ============================================================================
 */

#include "bowie/err.h"
#include "engine/internal/event.h"

bowie_error_t bowie_engine_event_push(bowie_engine_event_queue_t *q,
                                       const bowie_engine_event_t *ev)
{
    if (q == NULL || ev == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }

    if (q->count >= BOWIE_ENGINE_EVENT_CAP) {
        return BOWIE_ERR_TOO_LARGE;
    }

    q->events[q->tail] = *ev;
    q->tail = (q->tail + 1) % BOWIE_ENGINE_EVENT_CAP;
    q->count++;

    return BOWIE_OK;
}

bowie_error_t bowie_engine_event_pop(bowie_engine_event_queue_t *q,
                                      bowie_engine_event_t *out)
{
    if (q == NULL || out == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }

    if (q->count == 0) {
        return BOWIE_ERR_AGAIN;
    }

    *out = q->events[q->head];
    q->head = (q->head + 1) % BOWIE_ENGINE_EVENT_CAP;
    q->count--;

    return BOWIE_OK;
}

size_t bowie_engine_event_count(const bowie_engine_event_queue_t *q)
{
    if (q == NULL) {
        return 0;
    }

    return q->count;
}

/*
 * ============================================================================
 * END OF ENGINE EVENT IMPLEMENTATION
 * ============================================================================
 */
