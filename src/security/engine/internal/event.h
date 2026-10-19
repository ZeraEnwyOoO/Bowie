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
 * BOWIE — ENGINE: EVENT (INTERNAL)
 * ============================================================================
 *
 * Internal event queue for the engine.
 *
 * This header is internal to the Bowie library. It is not part
 * of the public API and is not installed.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No I/O.
 *   - No threading. The queue is not thread-safe; the caller
 *     must serialize access.
 *   - No public API. This header must not be included by
 *     anything outside src/engine/.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * The queue is a ring buffer of fixed-size events. The
 * capacity is a compile-time constant. Each event is a type
 * and a small payload; the payload is a fixed-size byte array
 * so that the event can be copied with a single memcpy.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <stdint.h>              uint8_t
 *   <stddef.h>              size_t
 *   "bowie/err.h"           errors
 * ============================================================================
 */

#ifndef BOWIE_ENGINE_INTERNAL_EVENT_H
#define BOWIE_ENGINE_INTERNAL_EVENT_H

#include <stdint.h>
#include <stddef.h>

#include "bowie/err.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ============================================================================
 * CONSTANTS
 * ============================================================================
 */

#define BOWIE_ENGINE_EVENT_CAP  64
#define BOWIE_ENGINE_EVENT_DATA 2048

/*
 * ============================================================================
 * TYPES
 * ============================================================================
 */

typedef enum bowie_engine_event_type {
    BOWIE_EVENT_PACKET_IN    = 1,
    BOWIE_EVENT_PACKET_OUT   = 2,
    BOWIE_EVENT_CONNECTED    = 3,
    BOWIE_EVENT_DISCONNECTED = 4,
    BOWIE_EVENT_ERROR        = 5
} bowie_engine_event_type_t;

typedef struct bowie_engine_event {
    bowie_engine_event_type_t type;
    size_t                    data_len;
    uint8_t                   data[BOWIE_ENGINE_EVENT_DATA];
} bowie_engine_event_t;

typedef struct bowie_engine_event_queue {
    bowie_engine_event_t events[BOWIE_ENGINE_EVENT_CAP];
    size_t               head;
    size_t               tail;
    size_t               count;
} bowie_engine_event_queue_t;

/*
 * ============================================================================
 * API
 * ============================================================================
 */

bowie_error_t bowie_engine_event_push(bowie_engine_event_queue_t *q,
                                       const bowie_engine_event_t *ev);

bowie_error_t bowie_engine_event_pop(bowie_engine_event_queue_t *q,
                                      bowie_engine_event_t *out);

size_t bowie_engine_event_count(const bowie_engine_event_queue_t *q);

/*
 * ============================================================================
 * END OF INTERNAL EVENT
 * ============================================================================
 */

#ifdef __cplusplus
}
#endif

#endif /* BOWIE_ENGINE_INTERNAL_EVENT_H */
