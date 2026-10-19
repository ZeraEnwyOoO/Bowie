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

#ifndef BOWIE_ENGINE_INTERNAL_EVENT_H
#define BOWIE_ENGINE_INTERNAL_EVENT_H

#include <stddef.h>

#include "bowie/types.h"
#include "bowie/err.h"
#include "bowie/hooks.h"
#include "engine/internal/engine.h" /* Includes the event struct now */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ============================================================================
 * LIFECYCLE
 * ============================================================================
 */

void bowie_engine_event_queue_clear(bowie_engine_event_queue_t *q);

/*
 * ============================================================================
 * PUSH
 * ============================================================================
 */

bowie_error_t bowie_engine_event_push(bowie_engine_event_queue_t *q,
                                      const bowie_event_record_t *rec);

/*
 * ============================================================================
 * DRAIN
 * ============================================================================
 */

void bowie_engine_event_drain(bowie_engine_event_queue_t *q,
                              bowie_event_hook_fn hook,
                              void *hook_userdata);

/*
 * ============================================================================
 * QUERY
 * ============================================================================
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
