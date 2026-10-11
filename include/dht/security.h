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
 * BOWIE — DHT SECURITY
 * ============================================================================
 *
 * Security checks for the DHT.
 *
 * The security module has two parts:
 *
 *   - Node ID verification: a node ID must be consistent with
 *     the address it claims.
 *   - Rate limiting: a node must not send too many requests
 *     in a short time.
 *
 * Both are optional. A DHT that does not need them runs with
 * the level BOWIE_DHT_SEC_NONE and pays nothing.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No authentication. A verified node ID is not a
 *     trustworthy identity; it is a check that the node is
 *     not trivially forging its address.
 *   - No encryption. The DHT messages are not encrypted.
 *   - No allocation. The rate-limit table is caller-supplied.
 *   - No persistence. The rate-limit table is in-memory.
 *   - No policy on which level to use. The DHT config
 *     decides; this module applies the level.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * Node ID verification.
 *
 * The check is the one in BEP 42: the first byte of the node
 * ID, modulo 8, must equal the last byte of the IPv4 address,
 * modulo 8. The check is a single comparison and costs
 * almost nothing.
 *
 * The check is not a strong defense. An attacker with many
 * IPv4 addresses can still forge many node IDs. The check
 * raises the cost of a Sybil attack from "one address, many
 * IDs" to "many addresses, many IDs". That is the intent.
 *
 * The check is IPv4 only. An IPv6 address has no single last
 * byte in the same sense; the BEP 42 rule is defined for
 * IPv4. A node with an IPv6 address is accepted without the
 * check when the level is BASIC. A future BEP defines the
 * IPv6 rule; this module does not guess.
 *
 * Rate limiting.
 *
 * The rate limiter is a small table of per-address counters.
 * The table is caller-supplied. A request from an address
 * that is not in the table adds an entry; a request from an
 * address that is in the table increments the counter. When
 * the counter exceeds the limit for the current window, the
 * request is rejected.
 *
 * The table is a fixed-size array. A new entry that does not
 * fit is rejected with BOWIE_ERR_TOO_SMALL; the caller
 * decides whether to evict an old entry. The table is small
 * and is not meant to be a complete history.
 *
 * The window is a fixed interval. The first request from an
 * address starts the window. When the window ends, the
 * counter is reset and the window restarts on the next
 * request. The window is not a sliding window; a burst at
 * the end of one window and the start of the next is
 * allowed.
 *
 * The rate limiter is not a security boundary. It is a
 * cheap defense against accidental flooding and against a
 * trivial attack. A determined attacker with many addresses
 * can still flood the node. The defense against that is the
 * node ID verification and the node's own capacity.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <stdint.h>                   uint8_t, uint32_t
 *   <stddef.h>                   size_t
 *   "bowie/types.h"              bowie_addr_t, bowie_mtime_t
 *   "bowie/err.h"                error codes
 *   "dht/types.h"                bowie_dht_node_id_t
 * ============================================================================
 */

#ifndef BOWIE_DHT_SECURITY_H
#define BOWIE_DHT_SECURITY_H

#include <stdint.h>
#include <stddef.h>

#include "bowie/types.h"
#include "bowie/err.h"
#include "dht/types.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ============================================================================
 * LEVEL
 * ============================================================================
 *
 * The level selects which checks are applied.
 *
 *   NONE     no checks. For a private DHT on a trusted
 *            network.
 *   BASIC    node ID verification only. For a public DHT
 *            where the node wants a cheap Sybil defense.
 *   STRICT   node ID verification and rate limiting. For a
 *            public DHT that is a target of flooding.
 */

typedef enum bowie_dht_sec_level {
    BOWIE_DHT_SEC_NONE   = 0,
    BOWIE_DHT_SEC_BASIC  = 1,
    BOWIE_DHT_SEC_STRICT = 2,
} bowie_dht_sec_level_t;

/*
 * ============================================================================
 * DEFAULTS
 * ============================================================================
 */

#define BOWIE_DHT_SEC_DEFAULT_MAX_REQUESTS  32u
#define BOWIE_DHT_SEC_DEFAULT_WINDOW_MS  60000u  /* 1 minute */

/*
 * ============================================================================
 * RATE LIMIT ENTRY
 * ============================================================================
 *
 * One entry in the rate-limit table. The entry is keyed by
 * address. The counter and the window start are per entry.
 *
 * The entry is a value type. The table is an array of
 * entries.
 */

typedef struct bowie_dht_rate_limit {
    bowie_addr_t   addr;
    uint32_t       count;
    bowie_mtime_t  window_start_ms;
} bowie_dht_rate_limit_t;

/*
 * ============================================================================
 * SECURITY STATE
 * ============================================================================
 *
 * The security state. It holds the level, the rate-limit
 * table, and the limit parameters.
 *
 * The table is caller-supplied. When the level is not STRICT,
 * the table is not used and may be NULL.
 *
 * The state is a value type. It is stored in the DHT engine
 * and copied with the engine.
 */

typedef struct bowie_dht_security {
    bowie_dht_sec_level_t   level;

    bowie_dht_rate_limit_t *limits;
    size_t                  limits_cap;
    size_t                  limits_used;

    uint32_t                max_requests_per_window;
    uint32_t                window_ms;
} bowie_dht_security_t;

/*
 * ============================================================================
 * LIFECYCLE
 * ============================================================================
 */

/*
 * Initialize a security state.
 *
 * The level selects the checks. The rate-limit table is
 * required when the level is STRICT; it may be NULL
 * otherwise.
 *
 * The max_requests_per_window and window_ms parameters
 * select the rate-limit policy. A value of 0 for either
 * one means "use the default".
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NULL_ARG if state is NULL.
 * Returns BOWIE_ERR_NULL_ARG if level is STRICT and the
 *   table is NULL.
 * Returns BOWIE_ERR_INVAL if the level is not one of the
 *   three defined values.
 */
bowie_error_t bowie_dht_security_init(
    bowie_dht_security_t   *state,
    bowie_dht_sec_level_t   level,
    bowie_dht_rate_limit_t *limits,
    size_t                  limits_cap,
    uint32_t                max_requests_per_window,
    uint32_t                window_ms);

/*
 * Reset a security state to the unset state.
 *
 * The level becomes NONE. The table pointers become NULL. The
 * counters become zero.
 *
 * Passing NULL is a no-op.
 */
void bowie_dht_security_clear(bowie_dht_security_t *state);

/*
 * ============================================================================
 * NODE ID VERIFICATION
 * ============================================================================
 */

/*
 * Check a node ID against an address.
 *
 * The rule is BEP 42: the low three bits of the first byte
 * of the node ID must equal the low three bits of the last
 * byte of the IPv4 address.
 *
 * The check is skipped (and the function returns 1) when:
 *
 *   - the level is NONE, or
 *   - the address is not IPv4.
 *
 * The check is applied when the level is BASIC or STRICT and
 * the address is IPv4.
 *
 * Returns 1 when the node ID is acceptable.
 * Returns 0 when the node ID does not match the address, or
 *   when any pointer is NULL.
 */
int bowie_dht_sec_node_id_ok(
    const bowie_dht_security_t *state,
    const bowie_dht_node_id_t  *id,
    const bowie_addr_t         *addr);

/*
 * Return the low three bits of the last byte of an IPv4
 * address.
 *
 * This is the value a node ID's first byte must match. A
 * caller that wants to generate a node ID uses this value.
 *
 * Returns 0 for a NULL pointer or a non-IPv4 address.
 */
uint8_t bowie_dht_sec_id_byte_for_addr(const bowie_addr_t *addr);

/*
 * ============================================================================
 * RATE LIMITING
 * ============================================================================
 */

/*
 * Check whether a request from an address is allowed.
 *
 * The function looks up the address in the table. A found
 * entry is incremented; the request is allowed when the new
 * count is less than or equal to max_requests_per_window.
 * A missing entry is added; the request is allowed.
 *
 * The window is a fixed interval. An entry whose window has
 * expired is reset: the count becomes 1 and the window
 * restarts. An entry whose window has not expired is
 * incremented.
 *
 * The level is not checked here. The caller decides whether
 * to call this function; the level STRICT implies the
 * caller should.
 *
 * Returns BOWIE_OK when the request is allowed.
 * Returns BOWIE_ERR_NULL_ARG if state or addr is NULL.
 * Returns BOWIE_ERR_TOO_SMALL if the table is full and the
 *   address is not in it.
 * Returns BOWIE_ERR_BUSY when the request is rejected by
 *   the rate limit.
 */
bowie_error_t bowie_dht_sec_check_rate(
    bowie_dht_security_t *state,
    const bowie_addr_t   *addr,
    bowie_mtime_t         now_ms);

/*
 * Reset the rate-limit table.
 *
 * The used counter becomes zero. The table's contents are
 * not required to be cleared; the entries are overwritten
 * on the next use.
 *
 * Passing NULL is a no-op.
 */
void bowie_dht_sec_rate_clear(bowie_dht_security_t *state);

/*
 * Return the number of entries in the rate-limit table.
 *
 * Returns 0 for NULL.
 */
size_t bowie_dht_sec_rate_count(
    const bowie_dht_security_t *state);

/*
 * ============================================================================
 * END OF DHT SECURITY
 * ============================================================================
 */

#ifdef __cplusplus
}
#endif

#endif /* BOWIE_DHT_SECURITY_H */
