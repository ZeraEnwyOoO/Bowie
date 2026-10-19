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
 * BOWIE — ENGINE EVENT QUEUE (IMPLEMENTATION)
 * ============================================================================
 *
 * Implementation of the engine event queue declared in
 * engine/internal/event.h.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No logging. Events are for the application; the log
 *     is a separate hook.
 *   - No allocation. The ring is a fixed-size array stored
 *     inline.
 *   - No filtering. Every push is recorded.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * The ring is a classic circular buffer. The head is the
 * next slot to write, the tail is the next slot to read,
 * and the count is the number of entries in the ring.
 *
 * A push when the ring is full overwrites the oldest entry.
 * The push returns BOWIE_ERR_OVERFLOW to tell the caller
 * that data was lost; the record is still written. A
 * caller that treats the overflow as fatal is wrong: the
 * event system is best-effort.
 *
 * The drain function copies the queue into a local array
 * under the lock, then calls the hook for each entry with
 * the lock released. This is what makes the hook able to
 * call back into the public API without deadlocking. The
 * public API's lock is recursive for the same reason.
 *
 * The local array is BOWIE_ENGINE_EVENT_QUEUE_CAP entries.
 * The queue is at most that size, so the copy always fits.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <string.h>              memcpy, memset
 *   "bowie/types.h"         bowie_event_record_t
 *   "bowie/err.h"           error codes
 *   "bowie/hooks.h"         bowie_event_hook_fn
 *   "engine/internal/event.h"  declarations
 * ============================================================================
 */

#include <string.h>

#include "bowie/types.h"
#include "bowie/err.h"
#include "bowie/hooks.h"
#include "engine/internal/event.h"

/*
 * ============================================================================
 * LIFECYCLE
 * ============================================================================
 */

void bowie_engine_event_queue_clear(bowie_engine_event_queue_t *q)
{
    if (q == NULL) {
        return;
    }
    memset(q, 0, sizeof(*q));
}

/*
 * ============================================================================
 * PUSH
 * ============================================================================
 */

bowie_error_t bowie_engine_event_push(bowie_engine_event_queue_t *q,
                                      const bowie_event_record_t *rec)
{
    bowie_error_t rc = BOWIE_OK;

    if (q == NULL || rec == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }

    /*
     * If the ring is full, the new record overwrites the
     * oldest. The tail advances and the count stays at the
     * capacity.
     */
    if (q->count == BOWIE_ENGINE_EVENT_QUEUE_CAP) {
        q->tail = (q->tail + 1u) % BOWIE_ENGINE_EVENT_QUEUE_CAP;
        q->count--;
        rc = BOWIE_ERR_OVERFLOW;
    }

    q->records[q->head] = *rec;
    q->head = (q->head + 1u) % BOWIE_ENGINE_EVENT_QUEUE_CAP;
    q->count++;

    return rc;
}

/*
 * ============================================================================
 * DRAIN
 * ============================================================================
 *
 * The drain function copies the queue into a local array
 * under the lock, then calls the hook for each entry with the
 * lock released.
 *
 * The local array is BOWIE_ENGINE_EVENT_QUEUE_CAP entries.
 * The queue is at most that size, so the copy always fits.
 *
 * The caller of this function must hold the engine lock. The
 * function releases the lock before calling the hook, and
 * re-acquires it before returning. The hook therefore runs
 * without the engine lock held.
 *
 * This is the only function in the engine that releases the
 * lock mid-call. The reason is deadlock: a hook that calls
 * back into the public API would deadlock if the lock were
 * still held by the drain.
 */

void bowie_engine_event_drain(bowie_engine_event_queue_t *q,
                              bowie_event_hook_fn hook,
                              void *hook_userdata)
{
    bowie_event_record_t local[BOWIE_ENGINE_EVENT_QUEUE_CAP];
    size_t               n;
    size_t               i;

    if (q == NULL) {
        return;
    }

    /*
     * Copy the queue into the local array. The copy is
     * performed with the ring's order preserved.
     */
    n = q->count;
    for (i = 0u; i < n; i++) {
        size_t idx = (q->tail + i) % BOWIE_ENGINE_EVENT_QUEUE_CAP;
        local[i] = q->records[idx];
    }

    /*
     * Reset the ring. The entries are not cleared; the
     * head and tail are reset and the count is zeroed.
     */
    q->head  = 0u;
    q->tail  = 0u;
    q->count = 0u;

    /*
     * If there is no hook, the events are dropped. The
     * caller is expected to have drained them for a reason;
     * dropping is the "no hook installed" case.
     */
    if (hook == NULL) {
        return;
    }

    /*
     * Call the hook for each event. The hook runs without
     * the engine lock held; the local array is on the
     * caller's stack and is valid for the duration of the
     * loop.
     */
    for (i = 0u; i < n; i++) {
        hook(&local[i], hook_userdata);
    }
}

/*
 * ============================================================================
 * QUERY
 * ============================================================================
 */

size_t bowie_engine_event_count(const bowie_engine_event_queue_t *q)
{
    if (q == NULL) {
        return 0u;
    }
    return q->count;
}

/*
 * ============================================================================
 * END OF FILE
 * ============================================================================
 */
