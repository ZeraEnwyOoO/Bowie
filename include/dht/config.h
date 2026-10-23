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
 * BOWIE — DHT CONFIG
 * ============================================================================
 *
 * The configuration of the DHT engine.
 *
 * The DHT config is separate from the Bowie config. The Bowie
 * config describes the engine as a whole; the DHT config
 * describes the DHT subsystem. A caller that uses the DHT
 * fills both.
 *
 * The DHT config is a value type. The engine copies it at
 * init time and uses the copy. The caller may free the
 * original after the engine is created.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No file parsing. The caller fills the struct.
 *   - No environment lookup.
 *   - No allocation.
 *   - No I/O.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * A zero-initialized config is valid and means "use the
 * defaults". The defaults function fills in the fields that
 * need non-zero values. The caller that wants only defaults
 * passes a zeroed struct to bowie_dht_config_defaults.
 *
 * The normalize function clamps out-of-range values and
 * fills in the defaults. It is safe to call on any config,
 * including a zeroed one. The validate function answers "is
 * this config usable?" and returns an error for a value that
 * normalize cannot fix.
 *
 * The bootstrap list is a fixed-size array of host-and-port
 * pairs. A host that is too long is rejected by validate.
 * The list is not sorted; the engine tries the entries in
 * the order they appear.
 *
 * The router flags are separate. A router that serves a
 * family network sets router_mode and bridge_mode. A router
 * that only bootstraps sets bootstrap_only. A router that
 * only relays sets relay_only. A flag that is not set is
 * zero.
 *
 * The security level selects the checks the DHT applies. See
 * dht/security.h for the levels.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <stdint.h>                   uint16_t, uint32_t
 *   <stddef.h>                   size_t
 *   "bowie/err.h"                error codes
 *   "dht/security.h"             bowie_dht_sec_level_t
 * ============================================================================
 */

#ifndef BOWIE_DHT_CONFIG_H
#define BOWIE_DHT_CONFIG_H

#include <stdint.h>
#include <stddef.h>

#include "bowie/err.h"
#include "dht/security.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ============================================================================
 * LIMITS
 * ============================================================================
 */

#define BOWIE_DHT_BOOTSTRAP_MAX      8
#define BOWIE_DHT_BOOTSTRAP_LEN_MAX  64

/*
 * ============================================================================
 * DEFAULTS
 * ============================================================================
 *
 * The values that the defaults function fills in. They are
 * documented here so that a caller can see them without
 * reading the source.
 *
 * The bucket count is the Kademlia maximum for a 160-bit ID.
 * A router with little RAM sets a smaller value.
 *
 * The peer lifetime is one hour. A peer that has not been
 * seen for an hour is stale.
 *
 * The token rotation is ten minutes. A token is valid for up
 * to twenty minutes (two rotation periods).
 *
 * The search timeout is thirty seconds. A search that has
 * not finished in thirty seconds is failed.
 */

#define BOWIE_DHT_DEFAULT_MAX_BUCKETS           160u
#define BOWIE_DHT_DEFAULT_MAX_NODES_PER_BUCKET    8u
#define BOWIE_DHT_DEFAULT_MAX_HASHES            256u
#define BOWIE_DHT_DEFAULT_MAX_PEERS_PER_HASH     16u
#define BOWIE_DHT_DEFAULT_MAX_STORAGE_PEERS    4096u
#define BOWIE_DHT_DEFAULT_REFRESH_INTERVAL_S    300u
#define BOWIE_DHT_DEFAULT_PEER_LIFETIME_S      3600u
#define BOWIE_DHT_DEFAULT_TOKEN_ROTATE_S        600u
#define BOWIE_DHT_DEFAULT_SEARCH_TIMEOUT_MS   30000u

/*
 * ============================================================================
 * BOOTSTRAP ENTRY
 * ============================================================================
 */

typedef struct bowie_dht_bootstrap {
    char     host[BOWIE_DHT_BOOTSTRAP_LEN_MAX];
    uint16_t port;
} bowie_dht_bootstrap_t;

/*
 * ============================================================================
 * DHT CONFIG
 * ============================================================================
 */

typedef struct bowie_dht_config {
    /* Optional thread-safe platform hook called before sending to a discovered
     * DHT endpoint. Returning zero prevents the send. */
    int (*prepare_underlay_address)(void *context, int family,
                                    const uint8_t *address, size_t address_len);
    void *underlay_context;

    /*
     * ----------------------------------------------------------------
     * Bootstrap
     * ----------------------------------------------------------------
     *
     * The nodes the engine contacts first. A router that is
     * the bootstrap node for a private network has an empty
     * list; the other nodes in the network point at it.
     */
    bowie_dht_bootstrap_t bootstrap[BOWIE_DHT_BOOTSTRAP_MAX];
    size_t                bootstrap_count;

    /*
     * ----------------------------------------------------------------
     * Limits
     * ----------------------------------------------------------------
     *
     * The sizes of the routing table and the storage. A
     * router with little RAM uses smaller values.
     */
    size_t   max_buckets;
    size_t   max_nodes_per_bucket;
    size_t   max_hashes;
    size_t   max_peers_per_hash;
    size_t   max_storage_peers;

    /*
     * ----------------------------------------------------------------
     * Timing
     * ----------------------------------------------------------------
     *
     * The intervals the engine uses for maintenance. The
     * values are in seconds, except the search timeout,
     * which is in milliseconds.
     */
    uint32_t refresh_interval_s;
    uint32_t peer_lifetime_s;
    uint32_t token_rotate_s;
    uint32_t search_timeout_ms;

    /*
     * ----------------------------------------------------------------
     * Security
     * ----------------------------------------------------------------
     *
     * The level selects the checks. The rate limit is the
     * number of requests per window; the window is one
     * minute and is not configurable.
     */
    bowie_dht_sec_level_t sec_level;
    uint32_t              max_requests_per_window;

    /*
     * ----------------------------------------------------------------
     * Behavior
     * ----------------------------------------------------------------
     *
     * The router flags. A flag that is zero is "off". A
     * device sets all flags to zero.
     *
     * router_mode        the node is a router
     * bridge_mode        the router bridges public and
     *                    private DHTs
     * bootstrap_only     the router does not join the
     *                    public DHT
     * relay_only         the router relays but does not
     *                    store
     * store_metadata     the storage keeps peer metadata
     */
    int      router_mode;
    int      bridge_mode;
    int      bootstrap_only;
    int      relay_only;
    int      store_metadata;

} bowie_dht_config_t;

/*
 * ============================================================================
 * DEFAULTS
 * ============================================================================
 */

/*
 * Fill a DHT config with the library defaults.
 *
 * The caller's bootstrap list and router flags are
 * preserved. Every other zero field is filled with the
 * default.
 *
 * Passing NULL is a programming error and returns
 * BOWIE_ERR_NULL_ARG without touching memory.
 */
bowie_error_t bowie_dht_config_defaults(bowie_dht_config_t *cfg);

/*
 * ============================================================================
 * VALIDATION
 * ============================================================================
 */

/*
 * Check whether a DHT config is usable.
 *
 * Returns BOWIE_OK when the config can be used as-is.
 * Returns an ARGUMENT-class error when a field is out of
 * range or inconsistent.
 *
 * The checks:
 *
 *   - max_buckets is between 1 and 160
 *   - max_nodes_per_bucket is between 1 and 64
 *   - max_hashes is greater than 0
 *   - max_peers_per_hash is greater than 0
 *   - max_storage_peers is at least max_hashes *
 *     max_peers_per_hash
 *   - bootstrap_count is at most BOWIE_DHT_BOOTSTRAP_MAX
 *   - each bootstrap entry has a non-empty host and a
 *     non-zero port
 *   - each bootstrap host is NUL-terminated
 *   - sec_level is a defined value
 *   - max_requests_per_window is greater than 0 when the
 *     level is STRICT
 *   - relay_only is not set together with store_metadata
 *     (a relay does not store)
 *
 * This function does not modify the config. Use normalize
 * to fix fixable problems.
 */
bowie_error_t bowie_dht_config_validate(
    const bowie_dht_config_t *cfg);

/*
 * Normalize a DHT config in place.
 *
 * Clamps out-of-range values into range, fills zero fields
 * with defaults, and applies the router presets.
 *
 * Safe to call on any config, including a zeroed one.
 *
 * Passing NULL is a programming error and returns
 * BOWIE_ERR_NULL_ARG without touching memory.
 */
bowie_error_t bowie_dht_config_normalize(bowie_dht_config_t *cfg);

/*
 * ============================================================================
 * BOOTSTRAP HELPERS
 * ============================================================================
 */

/*
 * Add a bootstrap entry to a config.
 *
 * The host is copied. The host must be shorter than
 * BOWIE_DHT_BOOTSTRAP_LEN_MAX. The port must be non-zero.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NULL_ARG if cfg or host is NULL.
 * Returns BOWIE_ERR_TOO_LARGE if the host is too long.
 * Returns BOWIE_ERR_TOO_SMALL if the list is full.
 * Returns BOWIE_ERR_INVAL if the port is zero.
 */
bowie_error_t bowie_dht_config_add_bootstrap(
    bowie_dht_config_t *cfg,
    const char         *host,
    uint16_t            port);

/*
 * Clear the bootstrap list.
 *
 * Passing NULL is a no-op.
 */
void bowie_dht_config_clear_bootstrap(bowie_dht_config_t *cfg);

/*
 * ============================================================================
 * END OF DHT CONFIG
 * ============================================================================
 */

#ifdef __cplusplus
}
#endif

#endif /* BOWIE_DHT_CONFIG_H */
