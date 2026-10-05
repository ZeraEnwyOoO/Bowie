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
 * BOWIE — CONFIGURATION
 * ============================================================================
 *
 * Configuration structure and validation for the Bowie engine.
 *
 * A bowie_config_t describes everything the engine needs to know
 * before it can start. The structure is caller-owned; the engine
 * copies what it needs at init time.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No file parsing. Reading a config file is an application
 *     concern. The library receives a filled structure.
 *   - No environment variable lookup. Same reason.
 *   - No dynamic allocation. The structure is fixed-size.
 *   - No platform detection. Platform is chosen at build time,
 *     not at runtime through this header.
 *   - No secrets. Private keys and passphrases are not part of
 *     this structure; they are provided to the specific API that
 *     needs them.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * Configuration is split into groups that match the engine's
 * layers:
 *
 *   - Identity: peer ID policy, keypair source
 *   - Network: DHT, NAT, tunnel, gateway
 *   - Security: grant lifetime, revocation policy
 *   - Runtime: timeouts, retries, limits
 *
 * A zero-initialized config is valid and means "use defaults
 * everywhere". The defaults function fills in the values that
 * differ from zero; a caller that wants only defaults can pass
 * a zeroed structure.
 *
 * Validation and normalization are separate:
 *
 *   - validate() answers "is this config usable?" and returns an
 *     error if not.
 *   - normalize() clamps values into the acceptable range and
 *     fills in defaults. It is safe to call on any config,
 *     including a partially-filled one.
 *
 * A caller that wants strict behavior calls validate() after
 * normalize(). A caller that wants tolerant behavior calls
 * normalize() only.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   "bowie/types.h"   shared types
 *   "bowie/err.h"     error codes
 * ============================================================================
 */

#ifndef BOWIE_CONFIG_H
#define BOWIE_CONFIG_H

#include <stdint.h>
#include <stddef.h>

#include "bowie/types.h"
#include "bowie/err.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ============================================================================
 * COMPILE-TIME LIMITS
 * ============================================================================
 */

#define BOWIE_CONFIG_INTERFACE_MAX 16
#define BOWIE_CONFIG_PEER_MAX      64

/*
 * ============================================================================
 * DEPLOYMENT MODE
 * ============================================================================
 *
 * The deployment mode tells the engine what environment it is
 * running in. The mode is platform-driven: the platform sets it
 * at startup based on what it is.
 *
 * This is not a fork. It is a capability preset.
 */

typedef enum bowie_mode {
    BOWIE_MODE_UNSET   = 0,
    BOWIE_MODE_DEVICE  = 1,
    BOWIE_MODE_ROUTER  = 2,
    BOWIE_MODE_BOX     = 3,
} bowie_mode_t;

/*
 * ============================================================================
 * CAPABILITIES
 * ============================================================================
 *
 * Capabilities are bit flags. A peer advertises what it can do,
 * not what role it plays.
 */

typedef enum bowie_cap {
    BOWIE_CAP_NONE     = 0,
    BOWIE_CAP_SOURCE   = 1u << 0,
    BOWIE_CAP_CLIENT   = 1u << 1,
    BOWIE_CAP_GATEWAY  = 1u << 2,
} bowie_cap_t;

/*
 * ============================================================================
 * LOG LEVEL
 * ============================================================================
 */

typedef enum bowie_log_level {
    BOWIE_LOG_NONE  = 0,
    BOWIE_LOG_ERROR = 1,
    BOWIE_LOG_WARN  = 2,
    BOWIE_LOG_INFO  = 3,
    BOWIE_LOG_DEBUG = 4,
    BOWIE_LOG_TRACE = 5,
} bowie_log_level_t;

/*
 * ============================================================================
 * CONFIGURATION STRUCTURE
 * ============================================================================
 *
 * Fixed-size, caller-owned. All fields are plain values.
 *
 * A zeroed structure means "use defaults everywhere". The
 * defaults function fills in the fields that need non-zero
 * values.
 */

typedef struct bowie_config {

    /*
     * ----------------------------------------------------------------
     * Identity
     * ----------------------------------------------------------------
     */

    /* Deployment mode. Set by the platform. */
    bowie_mode_t mode;

    /* Capability flags this peer advertises. */
    uint32_t capabilities;

    /* Preferred local interface name. Empty means auto. */
    char interface[BOWIE_CONFIG_INTERFACE_MAX];

    /*
     * ----------------------------------------------------------------
     * Network
     * ----------------------------------------------------------------
     */

    /* DHT bootstrap peer list. Empty means no bootstrap. */
    char bootstrap_peers[BOWIE_CONFIG_PEER_MAX][64];
    size_t bootstrap_peer_count;

    /* Enable DHT. */
    int dht_enabled;

    /* Enable NAT traversal through Xury. */
    int nat_enabled;

    /* Enable tunnel. */
    int tunnel_enabled;

    /* Enable gateway forwarding. */
    int gateway_enabled;

    /*
     * ----------------------------------------------------------------
     * Security
     * ----------------------------------------------------------------
     */

    /* Default grant lifetime in seconds. Zero means library default. */
    uint32_t grant_lifetime_sec;

    /* Enable revocation list. */
    int revocation_enabled;

    /*
     * ----------------------------------------------------------------
     * Runtime
     * ----------------------------------------------------------------
     */

    /* Log level. */
    bowie_log_level_t log_level;

    /* Maximum number of concurrent peer connections. */
    uint32_t max_peers;

    /* Maximum number of concurrent sessions. */
    uint32_t max_sessions;

    /* Default connect timeout in milliseconds. */
    uint32_t connect_timeout_ms;

    /* Default operation timeout in milliseconds. */
    uint32_t operation_timeout_ms;

    /* Number of worker threads. Zero means platform default. */
    uint32_t worker_threads;

} bowie_config_t;

/*
 * ============================================================================
 * DEFAULTS
 * ============================================================================
 */

/*
 * Fill a configuration with library defaults.
 *
 * The caller's mode and capabilities are preserved if set; all
 * other fields are overwritten with defaults.
 *
 * Passing NULL is a programming error and returns
 * BOWIE_ERR_NULL_ARG without touching memory.
 */
bowie_error_t bowie_config_defaults(bowie_config_t *cfg);

/*
 * ============================================================================
 * VALIDATION
 * ============================================================================
 */

/*
 * Check whether a configuration is usable.
 *
 * Returns BOWIE_OK when the configuration can be used as-is.
 * Returns an ARGUMENT-class error when a field is out of range
 * or inconsistent.
 *
 * This function does not modify the configuration. Use
 * normalize() to fix fixable problems.
 */
bowie_error_t bowie_config_validate(const bowie_config_t *cfg);

/*
 * Normalize a configuration in place.
 *
 * Clamps out-of-range values into range, fills zero fields with
 * defaults, and applies mode-dependent presets.
 *
 * Safe to call on any configuration, including a zeroed one.
 *
 * Passing NULL is a programming error and returns
 * BOWIE_ERR_NULL_ARG without touching memory.
 */
bowie_error_t bowie_config_normalize(bowie_config_t *cfg);

/*
 * ============================================================================
 * CAPABILITY HELPERS
 * ============================================================================
 */

/*
 * True when the capability mask contains the given flag.
 */
int bowie_cap_has(uint32_t mask, bowie_cap_t cap);

/*
 * Preset capability mask for a deployment mode.
 *
 * Device: SOURCE | CLIENT
 * Router: SOURCE | GATEWAY
 * Box:    SOURCE | GATEWAY
 * Unset:  NONE
 */
uint32_t bowie_cap_for_mode(bowie_mode_t mode);

/*
 * ============================================================================
 * END OF PUBLIC CONFIG
 * ============================================================================
 */

#ifdef __cplusplus
}
#endif

#endif /* BOWIE_CONFIG_H */
