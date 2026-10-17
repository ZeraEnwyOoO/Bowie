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
 * BOWIE — TIER1: QUOTA (IMPLEMENTATION)
 * ============================================================================
 *
 * Implementation of the quota helpers declared in
 * tier1/quota.h.
 *
 * The quota is a value type. The helpers are pure value
 * operations: they read a field, write a field, and compare
 * two values. They do not allocate, do not touch the network,
 * and do not depend on global state.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No enforcement. The gateway reads the quota and decides
 *     whether to forward a packet.
 *   - No time. The caller supplies the period start and
 *     resets the counter when the period rolls over.
 *   - No I/O.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * The "has data" check is a simple comparison: the used
 * counter is below the daily limit, or the limit is zero.
 *
 * The "has rate" check is a simple comparison: the rate
 * limit is non-zero. A rate limit of zero means "no limit",
 * which is the same convention as the daily limit.
 *
 * The add and subtract functions are written so that an
 * overflow or an underflow does not wrap. The add function
 * saturates at UINT64_MAX; the subtract function saturates at
 * zero. A caller that keeps the counter within the limit does
 * not hit either case, but a caller that adds a very large
 * number on purpose should not see the counter wrap.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <string.h>             memset
 *   "bowie/err.h"          errors
 *   "tier1/quota.h"        declarations
 * ============================================================================
 */

#include <string.h>

#include "bowie/err.h"
#include "tier1/quota.h"

/*
 * ============================================================================
 * LIFECYCLE
 * ============================================================================
 */

void bowie_quota_init(bowie_quota_t *q)
{
    if (q == NULL) {
        return;
    }

    memset(q, 0, sizeof(*q));
}

/*
 * ============================================================================
 * CHECK
 * ============================================================================
 */

int bowie_quota_has_data(const bowie_quota_t *q)
{
    if (q == NULL) {
        return 0;
    }

    /* Unlimited. */
    if (q->bytes_per_day == 0) {
        return 1;
    }

    return (q->bytes_used < q->bytes_per_day) ? 1 : 0;
}

int bowie_quota_has_rate(const bowie_quota_t *q)
{
    if (q == NULL) {
        return 0;
    }

    return (q->bits_per_second != 0) ? 1 : 0;
}

/*
 * ============================================================================
 * UPDATE
 * ============================================================================
 */

bowie_error_t bowie_quota_add(bowie_quota_t *q, uint64_t bytes)
{
    if (q == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }

    /*
     * Saturate at UINT64_MAX. A counter that has wrapped would
     * produce a wrong answer to "has data"; a counter that
     * saturates is still wrong, but in a direction the caller
     * can see.
     */
    if (UINT64_MAX - q->bytes_used < bytes) {
        q->bytes_used = UINT64_MAX;
    } else {
        q->bytes_used += bytes;
    }

    return BOWIE_OK;
}

bowie_error_t bowie_quota_subtract(bowie_quota_t *q, uint64_t bytes)
{
    if (q == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }

    /*
     * Saturate at zero. A negative counter is not representable;
     * a caller that subtracts more than it added has a bug, but
     * the counter is not left in an undefined state.
     */
    if (q->bytes_used < bytes) {
        q->bytes_used = 0;
    } else {
        q->bytes_used -= bytes;
    }

    return BOWIE_OK;
}

bowie_error_t bowie_quota_reset(bowie_quota_t *q, uint64_t period_start_ms)
{
    if (q == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }

    q->bytes_used   = 0;
    q->period_start = period_start_ms;

    return BOWIE_OK;
}

/*
 * ============================================================================
 * END OF TIER1 QUOTA IMPLEMENTATION
 * ============================================================================
 */
