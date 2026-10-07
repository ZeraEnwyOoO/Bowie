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
 * BOWIE — HOOKS IMPLEMENTATION
 * ============================================================================
 *
 * Hook-set helpers and event-name lookup for the integration
 * points declared in bowie/hooks.h.
 *
 * The hook set is a value type. It is copied by the engine at
 * init time; nothing here allocates, reads, or writes anything
 * outside the caller's structure.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No hook invocation. The engine calls the hooks; this file
 *     only manages the set.
 *   - No allocation. The hook set is a fixed-size value type.
 *   - No I/O. Nothing here writes to a file, a socket, or a log.
 *   - No threading. The hook set is caller-owned. Whether the
 *     engine calls a hook from the caller's thread or a worker
 *     thread is an engine decision, documented per hook.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * A cleared hook set is valid. The engine treats a cleared set
 * as "no hooks" and drops log and event output. This is the
 * same behavior as passing NULL hooks to the engine; the two
 * are equivalent.
 *
 * Validation checks internal consistency only. It does not
 * check that a hook is appropriate for the engine's current
 * state, because that is the engine's concern, not the set's.
 *
 * The rules are:
 *
 *   - A hook function may be set without userdata. A hook that
 *     does not need state is the common case.
 *
 *   - Userdata may not be set without the corresponding hook
 *     function. Userdata with no consumer is a caller mistake.
 *
 *   - A storage read hook and a storage write hook are
 *     independent. A caller may provide one without the other;
 *     the engine uses whatever is present.
 *
 * The event-name function returns a stable pointer to a static
 * string. The event list is currently a PROPOSAL; the names
 * may change when the event list is finalized, but the function
 * contract (stable pointer, never NULL) does not change.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <string.h>        memset
 *   "bowie/hooks.h"   the hook set and the declarations
 *   "bowie/err.h"     error codes
 * ============================================================================
 */

#include <string.h>

#include "bowie/hooks.h"
#include "bowie/err.h"

/*
 * ============================================================================
 * HOOK SET HELPERS
 * ============================================================================
 */

bowie_error_t bowie_hooks_clear(bowie_hooks_t *hooks)
{
    if (hooks == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }

    memset(hooks, 0, sizeof(*hooks));
    return BOWIE_OK;
}

bowie_error_t bowie_hooks_validate(const bowie_hooks_t *hooks)
{
    if (hooks == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }

    /*
     * Userdata without a function is a caller mistake: nothing
     * will ever read it.
     */
    if (hooks->log_userdata != NULL && hooks->log == NULL) {
        return BOWIE_ERR_INVAL;
    }
    if (hooks->event_userdata != NULL && hooks->event == NULL) {
        return BOWIE_ERR_INVAL;
    }
    if (hooks->storage_userdata != NULL &&
        hooks->storage_read == NULL &&
        hooks->storage_write == NULL) {
        return BOWIE_ERR_INVAL;
    }

    /*
     * A function without userdata is fine. A hook that needs no
     * state is the common case.
     */

    return BOWIE_OK;
}

/*
 * ============================================================================
 * EVENT NAMES
 * ============================================================================
 *
 * A stable pointer to a static string. Never NULL. Unknown
 * event codes return "UNKNOWN".
 *
 * The event list is currently a PROPOSAL, declared in
 * bowie/hooks.h. When the list is finalized, the names here
 * will be updated to match. The function contract does not
 * change.
 */

const char *bowie_event_name(bowie_event_t event)
{
    switch (event) {
    case BOWIE_EVENT_NONE:              return "NONE";

    case BOWIE_EVENT_ENGINE_STARTING:   return "ENGINE_STARTING";
    case BOWIE_EVENT_ENGINE_STARTED:    return "ENGINE_STARTED";
    case BOWIE_EVENT_ENGINE_STOPPING:   return "ENGINE_STOPPING";
    case BOWIE_EVENT_ENGINE_STOPPED:    return "ENGINE_STOPPED";

    case BOWIE_EVENT_PEER_FOUND:        return "PEER_FOUND";
    case BOWIE_EVENT_PEER_CONNECTED:    return "PEER_CONNECTED";
    case BOWIE_EVENT_PEER_DISCONNECTED: return "PEER_DISCONNECTED";
    case BOWIE_EVENT_PEER_FAILED:       return "PEER_FAILED";

    case BOWIE_EVENT_SESSION_OPENED:    return "SESSION_OPENED";
    case BOWIE_EVENT_SESSION_CLOSED:    return "SESSION_CLOSED";
    case BOWIE_EVENT_SESSION_DENIED:    return "SESSION_DENIED";

    case BOWIE_EVENT_GRANT_CREATED:     return "GRANT_CREATED";
    case BOWIE_EVENT_GRANT_REVOKED:     return "GRANT_REVOKED";
    case BOWIE_EVENT_GRANT_EXPIRED:     return "GRANT_EXPIRED";

    case BOWIE_EVENT_TUNNEL_UP:         return "TUNNEL_UP";
    case BOWIE_EVENT_TUNNEL_DOWN:       return "TUNNEL_DOWN";
    case BOWIE_EVENT_TUNNEL_ERROR:      return "TUNNEL_ERROR";

    case BOWIE_EVENT_GATEWAY_UP:        return "GATEWAY_UP";
    case BOWIE_EVENT_GATEWAY_DOWN:      return "GATEWAY_DOWN";
    case BOWIE_EVENT_GATEWAY_ERROR:     return "GATEWAY_ERROR";

    case BOWIE_EVENT_NAT_STARTED:       return "NAT_STARTED";
    case BOWIE_EVENT_NAT_SUCCEEDED:     return "NAT_SUCCEEDED";
    case BOWIE_EVENT_NAT_FAILED:        return "NAT_FAILED";

    case BOWIE_EVENT_ERROR:             return "ERROR";
    case BOWIE_EVENT_WARNING:           return "WARNING";

    default:                            return "UNKNOWN";
    }
}

/*
 * ============================================================================
 * END OF FILE
 * ============================================================================
 */
