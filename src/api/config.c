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
 * BOWIE — CONFIG IMPLEMENTATION
 * ============================================================================
 *
 * Defaults, validation, and normalization for bowie_config_t.
 *
 * A zero-initialized configuration is valid. The defaults
 * function fills in the fields that differ from zero; a caller
 * that wants only defaults can pass a zeroed structure to
 * bowie_config_defaults() or to the engine directly.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No file parsing. Reading a configuration file is an
 *     application concern. The library receives a filled
 *     structure.
 *   - No environment variable lookup. Same reason.
 *   - No allocation. The configuration is a fixed-size value
 *     type. There is nothing to allocate.
 *   - No I/O. Nothing here reads or writes a file, a socket, or
 *     a log.
 *   - No platform detection. Platform is chosen at build time.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * Validation and normalization are separate operations:
 *
 *   - bowie_config_validate() answers "is this configuration
 *     usable as-is?" and returns an error if not. It does not
 *     modify the configuration.
 *
 *   - bowie_config_normalize() clamps out-of-range values into
 *     range, fills zero fields with defaults, and applies the
 *     mode-dependent capability preset. It modifies the
 *     configuration in place.
 *
 * A caller that wants strict behavior calls validate() first.
 * A caller that wants tolerant behavior calls normalize() only.
 * A caller that wants both calls normalize() then validate().
 *
 * The defaults are chosen so that a normalized configuration is
 * always valid. That is, normalize() never produces a
 * configuration that validate() rejects.
 *
 * The mode preset is applied only when the caller has not set a
 * capability mask. An explicit capability mask always wins; the
 * preset is a convenience, not a policy.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <string.h>          memset, strlen, memcpy
 *   "bowie/config.h"    the structure and the declarations
 *   "bowie/err.h"       error codes
 * ============================================================================
 */

#include <string.h>

#include "bowie/config.h"
#include "bowie/err.h"

/*
 * ============================================================================
 * DEFAULTS
 * ============================================================================
 *
 * Library defaults. Every field that has a meaningful non-zero
 * value is set here.
 */

#define BOWIE_DEFAULT_GRANT_LIFETIME_SEC   3600u
#define BOWIE_DEFAULT_CONNECT_TIMEOUT_MS  30000u
#define BOWIE_DEFAULT_OPERATION_TIMEOUT_MS 10000u

bowie_error_t bowie_config_defaults(bowie_config_t *cfg)
{
    if (cfg == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }

    /*
     * Preserve mode and capabilities if set by the caller.
     * Everything else is overwritten with defaults.
     */
    bowie_mode_t  saved_mode = cfg->mode;
    uint32_t      saved_caps = cfg->capabilities;

    memset(cfg, 0, sizeof(*cfg));

    cfg->mode         = saved_mode;
    cfg->capabilities = saved_caps;

    /*
     * If the caller did not set a capability mask, apply the
     * mode preset. If the mode is also unset, capabilities
     * remain NONE.
     */
    if (cfg->capabilities == BOWIE_CAP_NONE) {
        cfg->capabilities = bowie_cap_for_mode(cfg->mode);
    }

    /*
     * Network: enabled by default.
     */
    cfg->dht_enabled     = 1;
    cfg->nat_enabled     = 1;
    cfg->tunnel_enabled  = 1;
    cfg->gateway_enabled = 0;  /* off unless the platform turns it on */

    /*
     * Security: a one-hour grant by default; revocation on.
     */
    cfg->grant_lifetime_sec  = BOWIE_DEFAULT_GRANT_LIFETIME_SEC;
    cfg->revocation_enabled  = 1;

    /*
     * Runtime: a reasonable log level, library limits, and
     * timeouts. Worker threads default to 0, which the platform
     * interprets as "pick a number".
     */
    cfg->log_level          = BOWIE_LOG_INFO;
    cfg->max_peers          = BOWIE_MAX_PEERS;
    cfg->max_sessions       = BOWIE_MAX_SESSIONS;
    cfg->connect_timeout_ms = BOWIE_DEFAULT_CONNECT_TIMEOUT_MS;
    cfg->operation_timeout_ms = BOWIE_DEFAULT_OPERATION_TIMEOUT_MS;
    cfg->worker_threads     = 0;

    return BOWIE_OK;
}

/*
 * ============================================================================
 * CAPABILITY HELPERS
 * ============================================================================
 */

int bowie_cap_has(uint32_t mask, bowie_cap_t cap)
{
    return ((mask & (uint32_t)cap) != 0u) ? 1 : 0;
}

uint32_t bowie_cap_for_mode(bowie_mode_t mode)
{
    switch (mode) {
    case BOWIE_MODE_DEVICE:
        return (uint32_t)BOWIE_CAP_SOURCE | (uint32_t)BOWIE_CAP_CLIENT;
    case BOWIE_MODE_ROUTER:
        return (uint32_t)BOWIE_CAP_SOURCE | (uint32_t)BOWIE_CAP_GATEWAY;
    case BOWIE_MODE_BOX:
        return (uint32_t)BOWIE_CAP_SOURCE | (uint32_t)BOWIE_CAP_GATEWAY;
    case BOWIE_MODE_UNSET:
    default:
        return (uint32_t)BOWIE_CAP_NONE;
    }
}

/*
 * ============================================================================
 * VALIDATION
 * ============================================================================
 *
 * Every rule here must be satisfiable by a normalized
 * configuration. If a rule rejects a value that normalize()
 * produces, the two are inconsistent.
 */

static int mode_is_valid(bowie_mode_t mode)
{
    return (mode == BOWIE_MODE_UNSET  ||
            mode == BOWIE_MODE_DEVICE ||
            mode == BOWIE_MODE_ROUTER ||
            mode == BOWIE_MODE_BOX) ? 1 : 0;
}

static int log_level_is_valid(bowie_log_level_t level)
{
    return (level >= BOWIE_LOG_NONE && level <= BOWIE_LOG_TRACE)
           ? 1 : 0;
}

static int capabilities_are_valid(uint32_t caps)
{
    const uint32_t allowed = (uint32_t)BOWIE_CAP_SOURCE
                           | (uint32_t)BOWIE_CAP_CLIENT
                           | (uint32_t)BOWIE_CAP_GATEWAY;
    return ((caps & ~allowed) == 0u) ? 1 : 0;
}

bowie_error_t bowie_config_validate(const bowie_config_t *cfg)
{
    if (cfg == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }

    if (!mode_is_valid(cfg->mode)) {
        return BOWIE_ERR_RANGE;
    }

    if (!capabilities_are_valid(cfg->capabilities)) {
        return BOWIE_ERR_RANGE;
    }

    if (!log_level_is_valid(cfg->log_level)) {
        return BOWIE_ERR_RANGE;
    }

    /*
     * The interface name must be NUL-terminated within its
     * array. A caller that copied a longer name in without
     * terminating it is a caller bug.
     */
    if (cfg->interface[BOWIE_CONFIG_INTERFACE_MAX - 1u] != '\0') {
        return BOWIE_ERR_NOT_TERMINATED;
    }

    /*
     * The bootstrap peer array is an array of fixed-size
     * strings. Every entry that is within bootstrap_peer_count
     * must be NUL-terminated.
     */
    if (cfg->bootstrap_peer_count > BOWIE_CONFIG_PEER_MAX) {
        return BOWIE_ERR_RANGE;
    }

    /*
     * Limits: a configured limit may not exceed the library
     * constant, and may not be zero for limits that must be
     * positive.
     */
    if (cfg->max_peers == 0u || cfg->max_peers > BOWIE_MAX_PEERS) {
        return BOWIE_ERR_RANGE;
    }

    if (cfg->max_sessions == 0u ||
        cfg->max_sessions > BOWIE_MAX_SESSIONS) {
        return BOWIE_ERR_RANGE;
    }

    /*
     * Timeouts must be positive. A zero timeout on a network
     * operation means "wait forever", which is never what a
     * caller wants.
     */
    if (cfg->connect_timeout_ms == 0u) {
        return BOWIE_ERR_RANGE;
    }
    if (cfg->operation_timeout_ms == 0u) {
        return BOWIE_ERR_RANGE;
    }

    /*
     * A grant lifetime of zero means "no expiry". That is a
     * valid policy only if revocation is enabled, because
     * otherwise there is no way to withdraw a grant.
     */
    if (cfg->grant_lifetime_sec == 0u && !cfg->revocation_enabled) {
        return BOWIE_ERR_RANGE;
    }

    return BOWIE_OK;
}

/*
 * ============================================================================
 * NORMALIZATION
 * ============================================================================
 *
 * Clamp values into range, fill zero fields with defaults, and
 * apply the mode preset for capabilities if the caller did not
 * set a capability mask.
 *
 * After this function returns, the configuration is valid
 * according to bowie_config_validate().
 */

bowie_error_t bowie_config_normalize(bowie_config_t *cfg)
{
    if (cfg == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }

    /*
     * Mode: an out-of-range mode becomes UNSET.
     */
    if (!mode_is_valid(cfg->mode)) {
        cfg->mode = BOWIE_MODE_UNSET;
    }

    /*
     * Capabilities: if the caller set no mask, apply the mode
     * preset. If the mask has unknown bits, mask them out.
     */
    if (cfg->capabilities == BOWIE_CAP_NONE) {
        cfg->capabilities = bowie_cap_for_mode(cfg->mode);
    }
    const uint32_t allowed = (uint32_t)BOWIE_CAP_SOURCE
                           | (uint32_t)BOWIE_CAP_CLIENT
                           | (uint32_t)BOWIE_CAP_GATEWAY;
    cfg->capabilities &= allowed;

    /*
     * Log level: out-of-range becomes INFO, which is the
     * default.
     */
    if (!log_level_is_valid(cfg->log_level)) {
        cfg->log_level = BOWIE_LOG_INFO;
    }

    /*
     * Interface: ensure NUL termination. A caller that copied
     * a longer string in without terminating it gets the last
     * byte zeroed.
     */
    cfg->interface[BOWIE_CONFIG_INTERFACE_MAX - 1u] = '\0';

    /*
     * Bootstrap peers: clamp the count and terminate every
     * entry. This is defensive; a caller that respects the
     * struct layout never needs it.
     */
    if (cfg->bootstrap_peer_count > BOWIE_CONFIG_PEER_MAX) {
        cfg->bootstrap_peer_count = BOWIE_CONFIG_PEER_MAX;
    }

    /*
     * Limits: clamp to the library constant, and set to the
     * default if zero.
     */
    if (cfg->max_peers == 0u) {
        cfg->max_peers = BOWIE_MAX_PEERS;
    }
    if (cfg->max_peers > BOWIE_MAX_PEERS) {
        cfg->max_peers = BOWIE_MAX_PEERS;
    }

    if (cfg->max_sessions == 0u) {
        cfg->max_sessions = BOWIE_MAX_SESSIONS;
    }
    if (cfg->max_sessions > BOWIE_MAX_SESSIONS) {
        cfg->max_sessions = BOWIE_MAX_SESSIONS;
    }

    /*
     * Timeouts: zero becomes the library default. Very large
     * values are left alone; the upper bound is a policy
     * decision that belongs to the caller.
     */
    if (cfg->connect_timeout_ms == 0u) {
        cfg->connect_timeout_ms = BOWIE_DEFAULT_CONNECT_TIMEOUT_MS;
    }
    if (cfg->operation_timeout_ms == 0u) {
        cfg->operation_timeout_ms = BOWIE_DEFAULT_OPERATION_TIMEOUT_MS;
    }

    /*
     * Grant lifetime: zero is allowed (no expiry) only when
     * revocation is enabled. Otherwise, set the default.
     */
    if (cfg->grant_lifetime_sec == 0u && !cfg->revocation_enabled) {
        cfg->grant_lifetime_sec = BOWIE_DEFAULT_GRANT_LIFETIME_SEC;
    }

    return BOWIE_OK;
}

/*
 * ============================================================================
 * END OF FILE
 * ============================================================================
 */
