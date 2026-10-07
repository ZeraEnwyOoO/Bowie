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
 * Clear, validation, and event-name lookup for the hook set.
 *
 * The hook set and the event record are declared in
 * bowie/hooks.h. This file provides the behavior behind them.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No dispatch. The engine calls hooks; this file does not.
 *   - No allocation. The hook set is a fixed-size value type.
 *     Clearing it is a memset, not a free.
 *   - No I/O. Nothing here writes to a file, a socket, or a log.
 *   - No event ordering. Event delivery order is an engine
 *     concern, not a hook-table concern.
 *   - No event payload construction. The engine fills the
 *     record; this file only names the event code.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * A hook set is valid when every userdata field is paired with
 * a function that will use it. A userdata pointer without a
 * function is a bug in the caller: the engine has no way to
 * call it. validate() rejects that case.
 *
 * The reverse is not an error. A function without userdata is
 * valid; the hook simply receives NULL for its userdata. That
 * is a normal way to write a hook that needs no state.
 *
 * The event name lookup is a switch, not a table, because the
 * set of event codes is small and the switch lets the compiler
 * warn on a missed case when a new code is added. The name
 * returned is the macro name without the BOWIE_EVENT_ prefix.
 *
 * bowie_event_name() never returns NULL. An unknown code
 * returns "UNKNOWN"; BOWIE_EVENT_NONE returns "NONE".
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <string.h>         memset
 *   "bowie/hooks.h"    the hook set and the declarations
 *   "bowie/err.h"      error codes
 * ============================================================================
 */

#include <string.h>

#include "bowie/hooks.h"
#include "bowie/err.h"

/*
 * ============================================================================
 * CLEAR
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

/*
 * ============================================================================
 * VALIDATION
 * ============================================================================
 *
 * A hook set is consistent when every userdata pointer is
 * paired with the function that consumes it.
 *
 *   - log_userdata      requires log
 *   - event_userdata    requires event
 *   - storage_userdata  requires storage_read or storage_write
 *
 * A function without userdata is always valid.
 */

bowie_error_t bowie_hooks_validate(const bowie_hooks_t *hooks)
{
    if (hooks == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }

    if (hooks->log_userdata != NULL && hooks->log == NULL) {
        return BOWIE_ERR_INVAL;
    }

    if (hooks->event_userdata != NULL && hooks->event == NULL) {
        return BOWIE_ERR_INVAL;
    }

    if (hooks->storage_userdata != NULL &&
        hooks->storage_read  == NULL &&
        hooks->storage_write == NULL) {
        return BOWIE_ERR_INVAL;
    }

    return BOWIE_OK;
}

/*
 * ============================================================================
 * EVENT NAME
 * ============================================================================
 *
 * The name returned is the macro identifier without the
 * BOWIE_EVENT_ prefix. BOWIE_EVENT_NONE returns "NONE". An
 * unknown code returns "UNKNOWN". The returned pointer is to a
 * static string and is never NULL.
 */

const char *bowie_event_name(bowie_event_t event)
{
    switch (event) {
    case BOWIE_EVENT_NONE:              return "NONE";

    /* Engine lifecycle. */
    case BOWIE_EVENT_ENGINE_STARTING:   return "ENGINE_STARTING";
    case BOWIE_EVENT_ENGINE_STARTED:    return "ENGINE_STARTED";
    case BOWIE_EVENT_ENGINE_STOPPING:   return "ENGINE_STOPPING";
    case BOWIE_EVENT_ENGINE_STOPPED:    return "ENGINE_STOPPED";

    /* Peer lifecycle. */
    case BOWIE_EVENT_PEER_FOUND:        return "PEER_FOUND";
    case BOWIE_EVENT_PEER_CONNECTED:    return "PEER_CONNECTED";
    case BOWIE_EVENT_PEER_DISCONNECTED: return "PEER_DISCONNECTED";
    case BOWIE_EVENT_PEER_FAILED:       return "PEER_FAILED";

    /* Session lifecycle. */
    case BOWIE_EVENT_SESSION_OPENED:    return "SESSION_OPENED";
    case BOWIE_EVENT_SESSION_CLOSED:    return "SESSION_CLOSED";
    case BOWIE_EVENT_SESSION_DENIED:    return "SESSION_DENIED";

    /* Permission lifecycle. */
    case BOWIE_EVENT_GRANT_CREATED:     return "GRANT_CREATED";
    case BOWIE_EVENT_GRANT_REVOKED:     return "GRANT_REVOKED";
    case BOWIE_EVENT_GRANT_EXPIRED:     return "GRANT_EXPIRED";

    /* Tunnel lifecycle. */
    case BOWIE_EVENT_TUNNEL_UP:         return "TUNNEL_UP";
    case BOWIE_EVENT_TUNNEL_DOWN:       return "TUNNEL_DOWN";
    case BOWIE_EVENT_TUNNEL_ERROR:      return "TUNNEL_ERROR";

    /* Gateway lifecycle. */
    case BOWIE_EVENT_GATEWAY_UP:        return "GATEWAY_UP";
    case BOWIE_EVENT_GATEWAY_DOWN:      return "GATEWAY_DOWN";
    case BOWIE_EVENT_GATEWAY_ERROR:     return "GATEWAY_ERROR";

    /* NAT traversal. */
    case BOWIE_EVENT_NAT_STARTED:       return "NAT_STARTED";
    case BOWIE_EVENT_NAT_SUCCEEDED:     return "NAT_SUCCEEDED";
    case BOWIE_EVENT_NAT_FAILED:        return "NAT_FAILED";

    /* Generic. */
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
