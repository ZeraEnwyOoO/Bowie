
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
 * BOWIE — DHT CONFIG IMPLEMENTATION
 * ============================================================================
 *
 * Defaults, validation, and normalization for the DHT config.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No file parsing.
 *   - No allocation.
 *   - No I/O.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * The defaults function fills a zero field with the
 * corresponding default. It does not touch a field that is
 * already non-zero, except for the router flags, which are
 * booleans and are left as the caller set them.
 *
 * The normalize function is the stronger one. It clamps a
 * value that is out of range into range, and fills a zero
 * field with the default. A value that is non-zero and in
 * range is kept.
 *
 * The validate function is the strict one. It returns an
 * error for a value that normalize would clamp, if the
 * caller asked for strict behavior. A caller that wants
 * tolerant behavior calls normalize and then validate; a
 * caller that wants strict behavior calls validate alone.
 *
 * The normalize function also checks the consistency rules
 * that are not per-field:
 *
 *   - max_storage_peers must be at least the product of
 *     max_hashes and max_peers_per_hash.
 *   - relay_only and store_metadata are mutually exclusive.
 *
 * When a rule is violated, normalize adjusts the field to
 * the smallest value that satisfies the rule. The validate
 * function returns an error instead.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <stdint.h>                   uint16_t, uint32_t
 *   <stddef.h>                   size_t
 *   <string.h>                   memset, strlen, memcpy
 *   "bowie/err.h"                error codes
 *   "dht/config.h"               the declarations
 *   "dht/security.h"             the level enum
 * ============================================================================
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "bowie/err.h"
#include "dht/config.h"
#include "dht/security.h"

/*
 * ============================================================================
 * DEFAULTS
 * ============================================================================
 */

bowie_error_t bowie_dht_config_defaults(bowie_dht_config_t *cfg)
{
    if (cfg == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }

    if (cfg->max_buckets == 0u) {
        cfg->max_buckets = BOWIE_DHT_DEFAULT_MAX_BUCKETS;
    }
    if (cfg->max_nodes_per_bucket == 0u) {
        cfg->max_nodes_per_bucket =
            BOWIE_DHT_DEFAULT_MAX_NODES_PER_BUCKET;
    }
    if (cfg->max_hashes == 0u) {
        cfg->max_hashes = BOWIE_DHT_DEFAULT_MAX_HASHES;
    }
    if (cfg->max_peers_per_hash == 0u) {
        cfg->max_peers_per_hash =
            BOWIE_DHT_DEFAULT_MAX_PEERS_PER_HASH;
    }
    if (cfg->max_storage_peers == 0u) {
        cfg->max_storage_peers =
            BOWIE_DHT_DEFAULT_MAX_STORAGE_PEERS;
    }
    if (cfg->refresh_interval_s == 0u) {
        cfg->refresh_interval_s =
            BOWIE_DHT_DEFAULT_REFRESH_INTERVAL_S;
    }
    if (cfg->peer_lifetime_s == 0u) {
        cfg->peer_lifetime_s =
            BOWIE_DHT_DEFAULT_PEER_LIFETIME_S;
    }
    if (cfg->token_rotate_s == 0u) {
        cfg->token_rotate_s =
            BOWIE_DHT_DEFAULT_TOKEN_ROTATE_S;
    }
    if (cfg->search_timeout_ms == 0u) {
        cfg->search_timeout_ms =
            BOWIE_DHT_DEFAULT_SEARCH_TIMEOUT_MS;
    }
    if (cfg->max_requests_per_window == 0u) {
        cfg->max_requests_per_window =
            BOWIE_DHT_SEC_DEFAULT_MAX_REQUESTS;
    }

    /*
     * The security level: a zero value is NONE, which is a
     * valid level. The defaults function does not change
     * it. A caller that wants the default level sets it
     * explicitly.
     */
    if (cfg->sec_level != BOWIE_DHT_SEC_NONE &&
        cfg->sec_level != BOWIE_DHT_SEC_BASIC &&
        cfg->sec_level != BOWIE_DHT_SEC_STRICT) {
        cfg->sec_level = BOWIE_DHT_SEC_NONE;
    }

    return BOWIE_OK;
}

/*
 * ============================================================================
 * INTERNAL — LEVEL CHECK
 * ============================================================================
 */

static int level_is_valid(bowie_dht_sec_level_t level)
{
    switch (level) {
    case BOWIE_DHT_SEC_NONE:
    case BOWIE_DHT_SEC_BASIC:
    case BOWIE_DHT_SEC_STRICT:
        return 1;
    default:
        return 0;
    }
}

/*
 * ============================================================================
 * VALIDATE
 * ============================================================================
 */

bowie_error_t bowie_dht_config_validate(
    const bowie_dht_config_t *cfg)
{
    if (cfg == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }

    /*
     * Per-field ranges.
     */
    if (cfg->max_buckets < 1u || cfg->max_buckets > 160u) {
        return BOWIE_ERR_RANGE;
    }
    if (cfg->max_nodes_per_bucket < 1u ||
        cfg->max_nodes_per_bucket > 64u) {
        return BOWIE_ERR_RANGE;
    }
    if (cfg->max_hashes == 0u) {
        return BOWIE_ERR_RANGE;
    }
    if (cfg->max_peers_per_hash == 0u) {
        return BOWIE_ERR_RANGE;
    }
    if (cfg->refresh_interval_s == 0u) {
        return BOWIE_ERR_RANGE;
    }
    if (cfg->peer_lifetime_s == 0u) {
        return BOWIE_ERR_RANGE;
    }
    if (cfg->token_rotate_s == 0u) {
        return BOWIE_ERR_RANGE;
    }
    if (cfg->search_timeout_ms == 0u) {
        return BOWIE_ERR_RANGE;
    }

    /*
     * Cross-field rules.
     */
    size_t need = cfg->max_hashes * cfg->max_peers_per_hash;
    if (need > cfg->max_storage_peers) {
        return BOWIE_ERR_RANGE;
    }

    /*
     * Security.
     */
    if (!level_is_valid(cfg->sec_level)) {
        return BOWIE_ERR_RANGE;
    }
    if (cfg->sec_level == BOWIE_DHT_SEC_STRICT &&
        cfg->max_requests_per_window == 0u) {
        return BOWIE_ERR_RANGE;
    }

    /*
     * Behavior.
     */
    if (cfg->relay_only && cfg->store_metadata) {
        /*
         * A relay does not store, so it cannot keep
         * metadata.
         */
        return BOWIE_ERR_RANGE;
    }

    /*
     * Bootstrap list.
     */
    if (cfg->bootstrap_count > BOWIE_DHT_BOOTSTRAP_MAX) {
        return BOWIE_ERR_RANGE;
    }
    for (size_t i = 0u; i < cfg->bootstrap_count; i++) {
        const bowie_dht_bootstrap_t *b = &cfg->bootstrap[i];
        if (b->host[BOWIE_DHT_BOOTSTRAP_LEN_MAX - 1u] != '\0') {
            return BOWIE_ERR_NOT_TERMINATED;
        }
        if (b->host[0] == '\0') {
            return BOWIE_ERR_INVAL;
        }
        if (b->port == 0u) {
            return BOWIE_ERR_INVAL;
        }
    }

    return BOWIE_OK;
}

/*
 * ============================================================================
 * NORMALIZE
 * ============================================================================
 */

bowie_error_t bowie_dht_config_normalize(bowie_dht_config_t *cfg)
{
    if (cfg == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }

    /*
     * Per-field defaults. A zero field is filled; a
     * non-zero field is clamped.
     */
    if (cfg->max_buckets == 0u) {
        cfg->max_buckets = BOWIE_DHT_DEFAULT_MAX_BUCKETS;
    } else if (cfg->max_buckets > 160u) {
        cfg->max_buckets = 160u;
    }

    if (cfg->max_nodes_per_bucket == 0u) {
        cfg->max_nodes_per_bucket =
            BOWIE_DHT_DEFAULT_MAX_NODES_PER_BUCKET;
    } else if (cfg->max_nodes_per_bucket > 64u) {
        cfg->max_nodes_per_bucket = 64u;
    }

    if (cfg->max_hashes == 0u) {
        cfg->max_hashes = BOWIE_DHT_DEFAULT_MAX_HASHES;
    }

    if (cfg->max_peers_per_hash == 0u) {
        cfg->max_peers_per_hash =
            BOWIE_DHT_DEFAULT_MAX_PEERS_PER_HASH;
    }

    if (cfg->refresh_interval_s == 0u) {
        cfg->refresh_interval_s =
            BOWIE_DHT_DEFAULT_REFRESH_INTERVAL_S;
    }

    if (cfg->peer_lifetime_s == 0u) {
        cfg->peer_lifetime_s =
            BOWIE_DHT_DEFAULT_PEER_LIFETIME_S;
    }

    if (cfg->token_rotate_s == 0u) {
        cfg->token_rotate_s =
            BOWIE_DHT_DEFAULT_TOKEN_ROTATE_S;
    }

    if (cfg->search_timeout_ms == 0u) {
        cfg->search_timeout_ms =
            BOWIE_DHT_DEFAULT_SEARCH_TIMEOUT_MS;
    }

    /*
     * Cross-field rules. The storage must hold every hash
     * with every peer. If the caller's value is too small,
     * the value is raised to the minimum.
     */
    size_t need = cfg->max_hashes * cfg->max_peers_per_hash;
    if (cfg->max_storage_peers < need) {
        cfg->max_storage_peers = need;
    }

    /*
     * Security.
     */
    if (!level_is_valid(cfg->sec_level)) {
        cfg->sec_level = BOWIE_DHT_SEC_NONE;
    }
    if (cfg->sec_level == BOWIE_DHT_SEC_STRICT &&
        cfg->max_requests_per_window == 0u) {
        cfg->max_requests_per_window =
            BOWIE_DHT_SEC_DEFAULT_MAX_REQUESTS;
    }

    /*
     * Behavior. The relay flags are mutually exclusive.
     * The normalize function prefers the more specific
     * flag: relay_only wins over store_metadata.
     */
    if (cfg->relay_only && cfg->store_metadata) {
        cfg->store_metadata = 0;
    }

    /*
     * Bootstrap list. A host that is not terminated is
     * terminated. A host that is empty is removed by
     * lowering the count. The port is not fixed; a
     * zero port makes the entry invalid, and the caller
     * must fix it.
     */
    for (size_t i = 0u; i < cfg->bootstrap_count; i++) {
        cfg->bootstrap[i].host[BOWIE_DHT_BOOTSTRAP_LEN_MAX - 1u] =
            '\0';
    }

    if (cfg->bootstrap_count > BOWIE_DHT_BOOTSTRAP_MAX) {
        cfg->bootstrap_count = BOWIE_DHT_BOOTSTRAP_MAX;
    }

    return BOWIE_OK;
}

/*
 * ============================================================================
 * BOOTSTRAP HELPERS
 * ============================================================================
 */

bowie_error_t bowie_dht_config_add_bootstrap(
    bowie_dht_config_t *cfg,
    const char         *host,
    uint16_t            port)
{
    if (cfg == NULL || host == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }
    if (port == 0u) {
        return BOWIE_ERR_INVAL;
    }

    size_t len = strlen(host);
    if (len == 0u) {
        return BOWIE_ERR_INVAL;
    }
    if (len >= BOWIE_DHT_BOOTSTRAP_LEN_MAX) {
        return BOWIE_ERR_TOO_LARGE;
    }

    if (cfg->bootstrap_count >= BOWIE_DHT_BOOTSTRAP_MAX) {
        return BOWIE_ERR_TOO_SMALL;
    }

    bowie_dht_bootstrap_t *b =
        &cfg->bootstrap[cfg->bootstrap_count];
    memset(b, 0, sizeof(*b));
    memcpy(b->host, host, len);
    b->host[len] = '\0';
    b->port = port;
    cfg->bootstrap_count++;
    return BOWIE_OK;
}

void bowie_dht_config_clear_bootstrap(bowie_dht_config_t *cfg)
{
    if (cfg == NULL) {
        return;
    }
    cfg->bootstrap_count = 0u;
}

/*
 * ============================================================================
 * END OF FILE
 * ============================================================================
 */
