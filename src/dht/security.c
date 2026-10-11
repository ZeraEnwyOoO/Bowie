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
 * BOWIE — DHT SECURITY IMPLEMENTATION
 * ============================================================================
 *
 * Node ID verification and rate limiting for the DHT.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No allocation.
 *   - No network.
 *   - No authentication.
 *   - No encryption.
 *   - No policy.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * The node ID check is BEP 42: the low three bits of the
 * first byte of the node ID must equal the low three bits of
 * the last byte of the IPv4 address.
 *
 * The rate limiter is a fixed-size array of per-address
 * entries. The lookup is a linear scan. The table is small;
 * the scan is fast.
 *
 * The window is fixed. An entry whose window has expired is
 * reset on the next request. A new entry starts a window on
 * its first request. The window is not a sliding window.
 *
 * The rate limiter returns BOWIE_ERR_BUSY when the request is
 * rejected. The DHT engine maps that to a message that is not
 * sent, or to a response with an error code. The choice is
 * the engine's.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <stdint.h>                   uint8_t, uint32_t
 *   <stddef.h>                   size_t
 *   <string.h>                   memset
 *   "bowie/types.h"              bowie_addr_t, bowie_mtime_t
 *   "bowie/err.h"                error codes
 *   "dht/types.h"                bowie_dht_node_id_t
 *   "dht/security.h"             the declarations
 * ============================================================================
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "bowie/types.h"
#include "bowie/err.h"
#include "dht/types.h"
#include "dht/security.h"

/*
 * ============================================================================
 * LIFECYCLE
 * ============================================================================
 */

bowie_error_t bowie_dht_security_init(
    bowie_dht_security_t   *state,
    bowie_dht_sec_level_t   level,
    bowie_dht_rate_limit_t *limits,
    size_t                  limits_cap,
    uint32_t                max_requests_per_window,
    uint32_t                window_ms)
{
    if (state == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }

    switch (level) {
    case BOWIE_DHT_SEC_NONE:
    case BOWIE_DHT_SEC_BASIC:
    case BOWIE_DHT_SEC_STRICT:
        break;
    default:
        return BOWIE_ERR_INVAL;
    }

    if (level == BOWIE_DHT_SEC_STRICT) {
        if (limits == NULL || limits_cap == 0u) {
            return BOWIE_ERR_NULL_ARG;
        }
    }

    memset(state, 0, sizeof(*state));
    state->level   = level;
    state->limits  = limits;
    state->limits_cap = limits_cap;
    state->limits_used = 0u;

    state->max_requests_per_window =
        (max_requests_per_window == 0u)
            ? BOWIE_DHT_SEC_DEFAULT_MAX_REQUESTS
            : max_requests_per_window;

    state->window_ms =
        (window_ms == 0u)
            ? BOWIE_DHT_SEC_DEFAULT_WINDOW_MS
            : window_ms;

    return BOWIE_OK;
}

void bowie_dht_security_clear(bowie_dht_security_t *state)
{
    if (state == NULL) {
        return;
    }
    state->level = BOWIE_DHT_SEC_NONE;
    state->limits = NULL;
    state->limits_cap = 0u;
    state->limits_used = 0u;
    state->max_requests_per_window = 0u;
    state->window_ms = 0u;
}

/*
 * ============================================================================
 * NODE ID VERIFICATION
 * ============================================================================
 */

uint8_t bowie_dht_sec_id_byte_for_addr(const bowie_addr_t *addr)
{
    if (addr == NULL) {
        return 0u;
    }
    if (addr->family != BOWIE_AF_INET) {
        return 0u;
    }
    return (uint8_t)(addr->addr[3] & 0x07u);
}

int bowie_dht_sec_node_id_ok(
    const bowie_dht_security_t *state,
    const bowie_dht_node_id_t  *id,
    const bowie_addr_t         *addr)
{
    if (state == NULL || id == NULL || addr == NULL) {
        return 0;
    }
    if (state->level == BOWIE_DHT_SEC_NONE) {
        return 1;
    }
    if (addr->family != BOWIE_AF_INET) {
        /*
         * BEP 42 does not define the rule for IPv6. A node
         * with an IPv6 address is accepted without the
         * check.
         */
        return 1;
    }

    uint8_t id_low = (uint8_t)(id->bytes[0] & 0x07u);
    uint8_t ip_low = (uint8_t)(addr->addr[3] & 0x07u);

    return (id_low == ip_low) ? 1 : 0;
}

/*
 * ============================================================================
 * RATE LIMITING
 * ============================================================================
 */

/*
 * Find an entry in the rate-limit table by address. Returns
 * the index, or -1 when the address is not in the table.
 */
static int find_rate_entry(const bowie_dht_security_t *state,
                           const bowie_addr_t         *addr)
{
    for (size_t i = 0u; i < state->limits_used; i++) {
        if (bowie_addr_equal(&state->limits[i].addr, addr)) {
            return (int)i;
        }
    }
    return -1;
}

bowie_error_t bowie_dht_sec_check_rate(
    bowie_dht_security_t *state,
    const bowie_addr_t   *addr,
    bowie_mtime_t         now_ms)
{
    if (state == NULL || addr == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }
    if (state->limits == NULL || state->limits_cap == 0u) {
        return BOWIE_ERR_INVAL;
    }

    int idx = find_rate_entry(state, addr);

    if (idx < 0) {
        /*
         * A new address. Add an entry with a fresh
         * window.
         */
        if (state->limits_used >= state->limits_cap) {
            return BOWIE_ERR_TOO_SMALL;
        }
        idx = (int)state->limits_used;
        state->limits[idx].addr = *addr;
        state->limits[idx].count = 1u;
        state->limits[idx].window_start_ms = now_ms;
        state->limits_used++;
        return BOWIE_OK;
    }

    bowie_dht_rate_limit_t *e = &state->limits[idx];

    /*
     * The clock may move backwards. Treat a backward
     * clock as "the window has not expired"; the
     * alternative is to reset the window and lose the
     * rate-limit state.
     */
    if (now_ms >= e->window_start_ms &&
        (now_ms - e->window_start_ms) >=
            (bowie_mtime_t)state->window_ms) {
        /*
         * The window has expired. Reset the counter and
         * start a new window.
         */
        e->count = 1u;
        e->window_start_ms = now_ms;
        return BOWIE_OK;
    }

    /*
     * The window has not expired. Increment the counter.
     */
    if (e->count >= state->max_requests_per_window) {
        return BOWIE_ERR_BUSY;
    }
    e->count++;
    return BOWIE_OK;
}

void bowie_dht_sec_rate_clear(bowie_dht_security_t *state)
{
    if (state == NULL) {
        return;
    }
    state->limits_used = 0u;
}

size_t bowie_dht_sec_rate_count(
    const bowie_dht_security_t *state)
{
    if (state == NULL) {
        return 0u;
    }
    return state->limits_used;
}

/*
 * ============================================================================
 * END OF FILE
 * ============================================================================
 */
