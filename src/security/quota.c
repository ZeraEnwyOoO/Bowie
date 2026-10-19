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
 * BOWIE — SECURITY: QUOTA (IMPLEMENTATION)
 * ============================================================================
 */

#include <string.h>

#include "bowie/err.h"
#include "security/quota.h"

void bowie_quota_init(bowie_quota_t *q)
{
    if (q == NULL) {
        return;
    }

    memset(q, 0, sizeof(*q));
}

int bowie_quota_has_data(const bowie_quota_t *q)
{
    if (q == NULL) {
        return 0;
    }

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

bowie_error_t bowie_quota_add(bowie_quota_t *q, uint64_t bytes)
{
    if (q == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }

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
