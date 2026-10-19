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
 * BOWIE — ENGINE EVENT QUEUE (INTERNAL)
 * ============================================================================
 *
 * The engine's event queue.
 *
 * The engine produces structured events as it runs: a peer
 * was found, a connection was established, a grant was
 * revoked, a tunnel went down. These events are recorded in
 * a fixed-size ring and delivered to the application through
 * the event hook installed at engine creation time.
 *
 * The event queue is the engine's side of the hook. The hook
 * (in bowie/hooks.h) is the application's side. The queue
 * decouples the two: an event is recorded whether or not a
 * hook is installed, and the hook is called from the
 * engine's thread, not from the thread that produced the
 * event.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No logging. The engine logs separately through the log
 *     hook. Events are for the application, not for the log.
 *   - No filtering. The queue records every event. A caller
 *     that wants to filter does so in its hook.
 *   - No allocation. The queue is a fixed-size ring stored
 *     inline in the engine.
 *   - No persistence. A full ring overwrites the oldest
 *     event. The application is expected to drain the queue
 *     as events arrive.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * The ring is small: BOWIE_ENGINE_EVENT_QUEUE_CAP entries.
 * The application is expected to drain the queue through its
 * hook, so a full queue is a sign that the application is
 * not keeping up, not a sign that the ring is too small.
 *
 * The queue is not thread-safe on its own. The engine's lock
 * protects it: producers take the lock to push, and the
 * drain function takes the lock to pop.
 *
 * The event record is the same one the public hook sees
 * (bowie_event_record_t in bowie/hooks.h). The queue does
 * not define a second record type; the two would drift
 * apart.
 *
 * The hook is called with the engine lock held. This is
 * deliberate: it means a hook can read engine state safely
 * (through the public API, which takes the lock again on
 * the same thread) but cannot call back into the engine in
 * a way that would deadlock. The public API's lock is a
 * recursive mutex for this reason.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <stddef.h>              size_t
 *   "bowie/types.h"         bowie_event_record_t
 *   "bowie/err.h"           bowie_error_t
 *   "bowie/hooks.h"         bowie_event_hook_fn
 *   "engine/internal/engine.h"  struct bowie_engine
 * ============================================================================
 */

#ifndef BOWIE_ENGINE_INTERNAL_EVENT_H
#define BOWIE_ENGINE_INTERNAL_EVENT_H

#include <stddef.h>

#include "bowie/types.h"
#include "bowie/err.h"
#include "bowie/hooks.h"
#include "engine/internal/engine.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ============================================================================
 * CONSTANTS
 * ============================================================================
 *
 * The size of the event ring. The application drains the
 * queue through its hook, so the ring does not need to be
 * large. 64 events is enough to hold a burst; a full ring is
 * a sign the application is not keeping up.
 */

#define BOWIE_ENGINE_EVENT_QUEUE_CAP 64u

/*
 * ============================================================================
 * QUEUE
 * ============================================================================
 *
 * A fixed-size ring of event records. The head is the next
 * slot to write, the tail is the next slot to read, and the
 * count is the number of entries currently in the ring.
 *
 * The ring is stored inline in the engine; it does not
 * allocate.
 */

typedef struct bowie_engine_event_queue {
    bowie_event_record_t records[BOWIE_ENGINE_EVENT_QUEUE_CAP];
    size_t               head;
    size_t               tail;
    size_t               count;
} bowie_engine_event_queue_t;

/*
 * ============================================================================
 * LIFECYCLE
 * ============================================================================
 */

/*
 * Reset a queue to empty.
 *
 * Passing NULL is a no-op.
 */
void bowie_engine_event_queue_clear(bowie_engine_event_queue_t *q);

/*
 * ============================================================================
 * PUSH
 * ============================================================================
 *
 * A producer calls push() to record an event. The record is
 * copied into the ring. If the ring is full, the oldest
 * event is overwritten; the count is not incremented past
 * the capacity.
 *
 * The caller must hold the engine lock.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NULL_ARG if q or rec is NULL.
 * Returns BOWIE_ERR_OVERFLOW if the ring overflowed (the
 *   oldest event was lost). The record was still written.
 */
bowie_error_t bowie_engine_event_push(bowie_engine_event_queue_t *q,
                                      const bowie_event_record_t *rec);

/*
 * ============================================================================
 * DRAIN
 * ============================================================================
 *
 * The drain function is the bridge between the queue and the
 * application's event hook. It pops every event from the
 * queue and calls the hook once per event.
 *
 * The function takes the lock once, copies the queue into a
 * local array, releases the lock, and then calls the hook
 * for each copied event. The hook therefore runs without the
 * engine lock held.
 *
 * If the hook is NULL, the events are drained and dropped.
 * This is the "no hook installed" case; the engine still
 * records the events, but nobody receives them.
 *
 * The engine lock must be held when the function is called,
 * but the function releases and re-acquires it. The caller
 * must not hold any other engine resource across the call.
 *
 * Passing NULL for q is a no-op.
 */
void bowie_engine_event_drain(bowie_engine_event_queue_t *q,
                              bowie_event_hook_fn hook,
                              void *hook_userdata);

/*
 * ============================================================================
 * QUERY
 * ============================================================================
 */

/*
 * Return the number of events currently in the queue.
 *
 * Passing NULL returns 0.
 */
size_t bowie_engine_event_count(const bowie_engine_event_queue_t *q);

/*
 * ============================================================================
 * END OF EVENT QUEUE
 * ============================================================================
 */

#ifdef __cplusplus
}
#endif

#endif /* BOWIE_ENGINE_INTERNAL_EVENT_H */
