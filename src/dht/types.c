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
 * BOWIE — DHT TYPES IMPLEMENTATION
 * ============================================================================
 *
 * Value operations for the DHT types.
 *
 * Every function is a pure value operation. The structs are
 * copied field by field, using memset and memcmp.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No allocation.
 *   - No I/O.
 *   - No policy.
 *   - No network.
 *   - No ownership.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * The four types share the same helper shape:
 *
 *   _clear()    zero the value
 *   _is_zero()  true when the value is unset
 *   _equal()    true when two values are equal
 *
 * The token is the only variable-length type. Its _is_zero()
 * checks the length, not the bytes. Its _equal() compares the
 * length first, then the bytes over the declared length.
 *
 * The distance is the only type without an _is_zero(). A zero
 * distance is a valid distance, not an unset value.
 *
 * A NULL pointer is treated as an unset value for the _is_zero
 * and _equal functions. This matches the convention used by
 * the peer ID helpers in bowie/types.h.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <string.h>                   memset, memcmp
 *   "dht/types.h"                the declarations
 * ============================================================================
 */

#include <string.h>

#include "dht/types.h"

/*
 * ============================================================================
 * NODE ID
 * ============================================================================
 */

void bowie_dht_node_id_clear(bowie_dht_node_id_t *id)
{
    if (id == NULL) {
        return;
    }
    memset(id, 0, sizeof(*id));
}

int bowie_dht_node_id_is_zero(const bowie_dht_node_id_t *id)
{
    if (id == NULL) {
        return 1;
    }

    for (size_t i = 0u; i < BOWIE_DHT_NODE_ID_LEN; i++) {
        if (id->bytes[i] != 0u) {
            return 0;
        }
    }
    return 1;
}

int bowie_dht_node_id_equal(const bowie_dht_node_id_t *a,
                            const bowie_dht_node_id_t *b)
{
    if (a == NULL && b == NULL) {
        return 1;
    }

    bowie_dht_node_id_t zero;
    bowie_dht_node_id_clear(&zero);

    const bowie_dht_node_id_t *id_a = (a != NULL) ? a : &zero;
    const bowie_dht_node_id_t *id_b = (b != NULL) ? b : &zero;

    return (memcmp(id_a->bytes, id_b->bytes,
                   BOWIE_DHT_NODE_ID_LEN) == 0) ? 1 : 0;
}

/*
 * ============================================================================
 * INFO HASH
 * ============================================================================
 */

void bowie_dht_info_hash_clear(bowie_dht_info_hash_t *h)
{
    if (h == NULL) {
        return;
    }
    memset(h, 0, sizeof(*h));
}

int bowie_dht_info_hash_is_zero(const bowie_dht_info_hash_t *h)
{
    if (h == NULL) {
        return 1;
    }

    for (size_t i = 0u; i < BOWIE_DHT_INFO_HASH_LEN; i++) {
        if (h->bytes[i] != 0u) {
            return 0;
        }
    }
    return 1;
}

int bowie_dht_info_hash_equal(const bowie_dht_info_hash_t *a,
                              const bowie_dht_info_hash_t *b)
{
    if (a == NULL && b == NULL) {
        return 1;
    }

    bowie_dht_info_hash_t zero;
    bowie_dht_info_hash_clear(&zero);

    const bowie_dht_info_hash_t *h_a = (a != NULL) ? a : &zero;
    const bowie_dht_info_hash_t *h_b = (b != NULL) ? b : &zero;

    return (memcmp(h_a->bytes, h_b->bytes,
                   BOWIE_DHT_INFO_HASH_LEN) == 0) ? 1 : 0;
}

/*
 * ============================================================================
 * TOKEN
 * ============================================================================
 */

void bowie_dht_token_clear(bowie_dht_token_t *t)
{
    if (t == NULL) {
        return;
    }
    memset(t, 0, sizeof(*t));
}

int bowie_dht_token_is_zero(const bowie_dht_token_t *t)
{
    if (t == NULL) {
        return 1;
    }
    return (t->len == 0u) ? 1 : 0;
}

int bowie_dht_token_equal(const bowie_dht_token_t *a,
                          const bowie_dht_token_t *b)
{
    if (a == NULL && b == NULL) {
        return 1;
    }

    bowie_dht_token_t zero;
    bowie_dht_token_clear(&zero);

    const bowie_dht_token_t *t_a = (a != NULL) ? a : &zero;
    const bowie_dht_token_t *t_b = (b != NULL) ? b : &zero;

    if (t_a->len != t_b->len) {
        return 0;
    }
    if (t_a->len == 0u) {
        return 1;
    }

    return (memcmp(t_a->bytes, t_b->bytes, t_a->len) == 0) ? 1 : 0;
}

/*
 * ============================================================================
 * DISTANCE
 * ============================================================================
 */

void bowie_dht_distance_clear(bowie_dht_distance_t *d)
{
    if (d == NULL) {
        return;
    }
    memset(d, 0, sizeof(*d));
}

int bowie_dht_distance_equal(const bowie_dht_distance_t *a,
                             const bowie_dht_distance_t *b)
{
    if (a == NULL && b == NULL) {
        return 1;
    }

    bowie_dht_distance_t zero;
    bowie_dht_distance_clear(&zero);

    const bowie_dht_distance_t *d_a = (a != NULL) ? a : &zero;
    const bowie_dht_distance_t *d_b = (b != NULL) ? b : &zero;

    return (memcmp(d_a->bytes, d_b->bytes,
                   BOWIE_DHT_DISTANCE_LEN) == 0) ? 1 : 0;
}

/*
 * ============================================================================
 * END OF FILE
 * ============================================================================
 */
