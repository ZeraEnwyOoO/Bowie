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
 * BOWIE — TIER1: QUOTA
 * ============================================================================
 *
 * Per-peer bandwidth and data quota management.
 *
 * The owner can set a limit on how much data a peer may use
 * and how fast the peer may send or receive. The quota is a
 * value type; the caller creates one, configures it, and
 * passes it to the gateway.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No enforcement. The gateway reads the quota and decides
 *     whether to forward a packet. This header only declares
 *     the value and the helpers.
 *   - No persistence. The quota lives in memory.
 *   - No time. A quota that resets daily needs a clock; the
 *     clock is supplied by the caller.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * A quota has two independent limits:
 *
 *   - bytes_per_day: the maximum number of bytes a peer may
 *     use in a 24-hour period. Zero means unlimited.
 *
 *   - bits_per_second: the maximum sustained rate. Zero means
 *     unlimited.
 *
 * The two limits are independent. A peer can be unlimited in
 * data but limited in rate, or limited in data but unlimited
 * in rate, or limited in both, or limited in neither.
 *
 * The quota carries a usage counter. The gateway updates it as
 * packets are forwarded. The counter is reset by the caller
 * when the day rolls over; this module does not track the day
 * itself.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <stdint.h>              uint32_t, uint64_t
 *   "bowie/err.h"           bowie_error_t
 * ============================================================================
 */

#ifndef BOWIE_TIER1_QUOTA_H
#define BOWIE_TIER1_QUOTA_H

#include <stdint.h>

#include "bowie/err.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ============================================================================
 * QUOTA
 * ============================================================================
 *
 * A quota is a plain value struct. It can be copied, stored,
 * and passed around without allocation.
 *
 * bytes_per_day   0 means unlimited.
 * bits_per_second 0 means unlimited.
 * bytes_used      the number of bytes used in the current
 *                 period. The gateway increments it.
 * period_start    the wall-clock time the current period
 *                 started, in milliseconds. The caller sets it
 *                 when the quota is created and resets it when
 *                 the period rolls over.
 */

typedef struct bowie_quota {
    uint64_t bytes_per_day;
    uint64_t bits_per_second;
    uint64_t bytes_used;
    uint64_t period_start;
} bowie_quota_t;

/*
 * ============================================================================
 * LIFECYCLE
 * ============================================================================
 */

/*
 * Fill a quota with default values.
 *
 * Defaults: bytes_per_day = 0, bits_per_second = 0,
 * bytes_used = 0, period_start = 0. A quota with these
 * defaults is unlimited.
 *
 * Passing NULL is a no-op.
 */
void bowie_quota_init(bowie_quota_t *q);

/*
 * ============================================================================
 * CHECK
 * ============================================================================
 */

/*
 * True when the peer has used less than its daily byte limit.
 *
 * Returns 1 when the peer may send more data, 0 when the
 * peer is over its limit. A quota with bytes_per_day = 0 is
 * always under its limit.
 *
 * Passing NULL returns 0.
 */
int bowie_quota_has_data(const bowie_quota_t *q);

/*
 * True when the peer is within its rate limit.
 *
 * The rate limit is a long-term average, not an instantaneous
 * limit. A caller that needs a strict token bucket does that
 * itself. This function only reports whether the quota is
 * unlimited in rate.
 *
 * Returns 1 when the quota has no rate limit, 0 when it has
 * one. The gateway uses this to decide whether to apply rate
 * shaping at all.
 *
 * Passing NULL returns 0.
 */
int bowie_quota_has_rate(const bowie_quota_t *q);

/*
 * ============================================================================
 * UPDATE
 * ============================================================================
 */

/*
 * Add to the used-byte counter.
 *
 * The counter is incremented by the given number of bytes. A
 * caller that wants to subtract (for example, when a packet
 * is dropped) calls the function with a negative value, which
 * is not representable here; the caller must use
 * bowie_quota_subtract() instead.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NULL_ARG if q is NULL.
 */
bowie_error_t bowie_quota_add(bowie_quota_t *q, uint64_t bytes);

/*
 * Subtract from the used-byte counter.
 *
 * The counter is decremented by the given number of bytes. If
 * the result would be negative, the counter is set to zero.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NULL_ARG if q is NULL.
 */
bowie_error_t bowie_quota_subtract(bowie_quota_t *q, uint64_t bytes);

/*
 * Reset the used-byte counter and set a new period start.
 *
 * The caller calls this when the period rolls over (for
 * example, at midnight local time). The module does not track
 * time itself.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NULL_ARG if q is NULL.
 */
bowie_error_t bowie_quota_reset(bowie_quota_t *q, uint64_t period_start_ms);

/*
 * ============================================================================
 * END OF TIER1 QUOTA
 * ============================================================================
 */

#ifdef __cplusplus
}
#endif

#endif /* BOWIE_TIER1_QUOTA_H */
