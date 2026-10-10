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
 * BOWIE — BENCODE IMPLEMENTATION
 * ============================================================================
 *
 * Bencode encoding and decoding for the DHT layer.
 *
 * The file is organized in three parts:
 *
 *   1. Decode: parse a bencoded buffer into an arena of values.
 *   2. Access: read a decoded value.
 *   3. Encode: write a value tree into a caller-supplied buffer.
 *
 * The three parts share no state. A caller that only decodes
 * does not pay for the encoder, and vice versa.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No allocation. Every function writes into a
 *     caller-supplied arena or buffer.
 *   - No I/O.
 *   - No schema.
 *   - No streaming.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * The decoder is a recursive descent parser over a borrowed
 * input span. The recursion depth is bounded by the nesting
 * depth of the input. A malicious input can nest deeply enough
 * to overflow the C stack. The decoder limits the depth to
 * BOWIE_BENCODE_MAX_DEPTH and reports BOWIE_ERR_FORMAT when
 * the limit is exceeded.
 *
 * The decoder is strict by default. In lenient mode it accepts
 * three deviations:
 *
 *   - An integer with a leading zero (other than "0").
 *   - A negative zero.
 *   - A dictionary whose keys are not sorted.
 *
 * A deviation sets arena->lenient_used to 1 and is not an
 * error. A caller that wants strict behavior passes
 * allow_lenient == 0.
 *
 * The decoder fills two arrays: one for values, one for
 * dictionary entries. The two arrays are separate because a
 * dictionary entry is a key-value pair, not a value. The
 * dict's "first" index is into the entry array; the entry's
 * "value_index" is into the value array.
 *
 * A byte string and a dictionary key are borrowed spans. They
 * point into the input buffer. The caller must keep the input
 * buffer alive for as long as it uses the decoded value.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <stdint.h>                   int64_t, uint8_t
 *   <stddef.h>                   size_t
 *   <string.h>                   memcmp
 *   "bowie/types.h"              bowie_span_t
 *   "bowie/err.h"                error codes
 *   "dht/bencode.h"              the declarations
 * ============================================================================
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "bowie/types.h"
#include "bowie/err.h"
#include "dht/bencode.h"

/*
 * ============================================================================
 * INTERNAL — DEPTH LIMIT
 * ============================================================================
 *
 * The maximum nesting depth. A list inside a list inside a
 * list ... deeper than this is rejected. The limit is
 * generous for any real DHT message and small enough that the
 * recursion cannot overflow a typical C stack.
 */

#define BOWIE_BENCODE_MAX_DEPTH 32

/*
 * ============================================================================
 * INTERNAL — PARSER STATE
 * ============================================================================
 */

typedef struct parser {
    const uint8_t *buf;
    size_t         len;
    size_t         pos;
    int            allow_lenient;

    bowie_bencode_arena_t *arena;
} parser_t;

/*
 * ============================================================================
 * INTERNAL — ARENA ALLOCATION
 * ============================================================================
 *
 * The decoder allocates values and entries from the arena. A
 * value is allocated by index; the caller receives the index,
 * not a pointer, because the array may be reallocated by a
 * future version of this module. The current version never
 * reallocates, but the index is the interface.
 *
 * An allocation that does not fit is reported as
 * BOWIE_ERR_TOO_SMALL.
 */

static bowie_error_t arena_alloc_value(bowie_bencode_arena_t *a,
                                       size_t *out_index)
{
    if (a->values_used >= a->values_cap) {
        return BOWIE_ERR_TOO_SMALL;
    }
    *out_index = a->values_used++;
    return BOWIE_OK;
}

static bowie_error_t arena_alloc_entry(bowie_bencode_arena_t *a,
                                       size_t *out_index)
{
    if (a->entries_used >= a->entries_cap) {
        return BOWIE_ERR_TOO_SMALL;
    }
    *out_index = a->entries_used++;
    return BOWIE_OK;
}

/*
 * ============================================================================
 * INTERNAL — CHARACTER TESTS
 * ============================================================================
 */

static int is_digit(uint8_t c)
{
    return (c >= (uint8_t)'0' && c <= (uint8_t)'9') ? 1 : 0;
}

/*
 * ============================================================================
 * INTERNAL — INTEGER PARSING
 * ============================================================================
 *
 * Parse an integer. The input starts after the 'i'. The
 * function reads until 'e'.
 *
 * The integer is signed. A leading '-' is allowed. A leading
 * '+' is not. A leading zero is not allowed unless the value
 * is exactly "0". A negative zero is not allowed.
 *
 * In lenient mode, a leading zero and a negative zero are
 * accepted and the lenient flag is set.
 *
 * The value is accumulated in a signed 64-bit integer. An
 * overflow is reported as BOWIE_ERR_TOO_LARGE.
 */

static bowie_error_t parse_integer(parser_t *p, int64_t *out)
{
    int      negative = 0;
    int      lenient  = 0;
    uint64_t acc      = 0u;
    int      digits   = 0;

    if (p->pos >= p->len) {
        return BOWIE_ERR_FORMAT;
    }

    if (p->buf[p->pos] == (uint8_t)'-') {
        negative = 1;
        p->pos++;
    }

    if (p->pos >= p->len) {
        return BOWIE_ERR_FORMAT;
    }

    if (p->buf[p->pos] == (uint8_t)'0') {
        /*
         * A leading zero is allowed only if the value is
         * exactly "0". If the next byte is a digit, the
         * value has a leading zero.
         */
        if (p->pos + 1u < p->len &&
            is_digit(p->buf[p->pos + 1u])) {
            if (!p->allow_lenient) {
                return BOWIE_ERR_FORMAT;
            }
            lenient = 1;
        }
        acc = 0u;
        digits = 1;
        p->pos++;
    } else if (is_digit(p->buf[p->pos])) {
        while (p->pos < p->len && is_digit(p->buf[p->pos])) {
            uint8_t d = (uint8_t)(p->buf[p->pos] - (uint8_t)'0');
            if (acc > (UINT64_MAX - (uint64_t)d) / 10u) {
                return BOWIE_ERR_TOO_LARGE;
            }
            acc = acc * 10u + (uint64_t)d;
            digits++;
            p->pos++;
        }
    } else {
        return BOWIE_ERR_FORMAT;
    }

    if (p->pos >= p->len || p->buf[p->pos] != (uint8_t)'e') {
        return BOWIE_ERR_FORMAT;
    }
    p->pos++;

    if (digits == 0) {
        return BOWIE_ERR_FORMAT;
    }

    if (negative && acc == 0u) {
        /*
         * A negative zero. Accepted in lenient mode.
         */
        if (!p->allow_lenient) {
            return BOWIE_ERR_FORMAT;
        }
        lenient = 1;
    }

    /*
     * Range check against int64_t.
     */
    if (negative) {
        if (acc > (uint64_t)INT64_MAX + 1u) {
            return BOWIE_ERR_TOO_LARGE;
        }
        if (acc == (uint64_t)INT64_MAX + 1u) {
            *out = INT64_MIN;
        } else {
            *out = -(int64_t)acc;
        }
    } else {
        if (acc > (uint64_t)INT64_MAX) {
            return BOWIE_ERR_TOO_LARGE;
        }
        *out = (int64_t)acc;
    }

    if (lenient) {
        p->arena->lenient_used = 1;
    }

    return BOWIE_OK;
}

/*
 * ============================================================================
 * INTERNAL — BYTE STRING PARSING
 * ============================================================================
 *
 * Parse a byte string. The input starts at a digit; the
 * function reads the length, then ':', then that many bytes.
 *
 * The length is a decimal number with no leading zero, except
 * that "0" is allowed. An overflow of the length is reported
 * as BOWIE_ERR_TOO_LARGE.
 *
 * The returned span points into the input buffer.
 */

static bowie_error_t parse_string(parser_t *p, bowie_span_t *out)
{
    size_t len = 0u;
    int    digits = 0;

    if (p->pos >= p->len) {
        return BOWIE_ERR_FORMAT;
    }

    if (p->buf[p->pos] == (uint8_t)'0') {
        if (p->pos + 1u < p->len &&
            is_digit(p->buf[p->pos + 1u])) {
            if (!p->allow_lenient) {
                return BOWIE_ERR_FORMAT;
            }
            p->arena->lenient_used = 1;
        }
        len = 0u;
        digits = 1;
        p->pos++;
    } else if (is_digit(p->buf[p->pos])) {
        while (p->pos < p->len && is_digit(p->buf[p->pos])) {
            uint8_t d = (uint8_t)(p->buf[p->pos] - (uint8_t)'0');
            if (len > (SIZE_MAX - (size_t)d) / 10u) {
                return BOWIE_ERR_TOO_LARGE;
            }
            len = len * 10u + (size_t)d;
            digits++;
            p->pos++;
        }
    } else {
        return BOWIE_ERR_FORMAT;
    }

    if (digits == 0) {
        return BOWIE_ERR_FORMAT;
    }

    if (p->pos >= p->len || p->buf[p->pos] != (uint8_t)':') {
        return BOWIE_ERR_FORMAT;
    }
    p->pos++;

    if (len > p->len - p->pos) {
        return BOWIE_ERR_FORMAT;
    }

    out->data = p->buf + p->pos;
    out->len  = len;
    p->pos   += len;

    return BOWIE_OK;
}

/*
 * ============================================================================
 * INTERNAL — RECURSIVE PARSE
 * ============================================================================
 *
 * Parse one value. The kind is determined by the first byte:
 *
 *   'i'  integer
 *   'l'  list
 *   'd'  dictionary
 *   '0'-'9'  byte string
 *
 * A list or dictionary is parsed recursively. The depth is
 * checked at entry.
 *
 * On success, the value index is written through out_index.
 */

static bowie_error_t parse_value(parser_t *p, int depth,
                                 size_t *out_index);

static bowie_error_t parse_list(parser_t *p, int depth,
                                size_t *out_index)
{
    /*
     * The list opener 'l' has already been consumed.
     */
    size_t first = 0u;
    size_t count = 0u;
    int    first_set = 0;

    while (p->pos < p->len && p->buf[p->pos] != (uint8_t)'e') {
        size_t child = 0u;
        bowie_error_t rc = parse_value(p, depth + 1, &child);
        if (rc != BOWIE_OK) {
            return rc;
        }
        if (!first_set) {
            first = child;
            first_set = 1;
        }
        count++;
    }

    if (p->pos >= p->len) {
        return BOWIE_ERR_FORMAT;
    }
    p->pos++; /* consume 'e' */

    size_t idx = 0u;
    bowie_error_t rc = arena_alloc_value(p->arena, &idx);
    if (rc != BOWIE_OK) {
        return rc;
    }

    bowie_bencode_value_t *v = &p->arena->values[idx];
    v->kind = BOWIE_BENCODE_LIST;
    v->u.list.first = first;
    v->u.list.count = count;

    *out_index = idx;
    return BOWIE_OK;
}

static bowie_error_t parse_dict(parser_t *p, int depth,
                                size_t *out_index)
{
    /*
     * The dict opener 'd' has already been consumed.
     */
    size_t first = 0u;
    size_t count = 0u;
    int    first_set = 0;

    bowie_span_t prev_key = { NULL, 0u };
    int          have_prev = 0;

    while (p->pos < p->len && p->buf[p->pos] != (uint8_t)'e') {
        bowie_span_t key = { NULL, 0u };
        bowie_error_t rc = parse_string(p, &key);
        if (rc != BOWIE_OK) {
            return rc;
        }

        /*
         * Keys must be sorted in byte order. In strict
         * mode an unsorted key is an error; in lenient
         * mode the deviation is noted.
         */
        if (have_prev) {
            size_t min = (prev_key.len < key.len)
                       ? prev_key.len : key.len;
            int cmp = memcmp(prev_key.data, key.data, min);
            int unsorted;
            if (cmp < 0) {
                unsorted = 0;
            } else if (cmp > 0) {
                unsorted = 1;
            } else {
                unsorted = (prev_key.len >= key.len) ? 1 : 0;
            }
            if (unsorted) {
                if (!p->allow_lenient) {
                    return BOWIE_ERR_FORMAT;
                }
                p->arena->lenient_used = 1;
            }
        }

        size_t val_idx = 0u;
        rc = parse_value(p, depth + 1, &val_idx);
        if (rc != BOWIE_OK) {
            return rc;
        }

        size_t ent_idx = 0u;
        rc = arena_alloc_entry(p->arena, &ent_idx);
        if (rc != BOWIE_OK) {
            return rc;
        }

        bowie_bencode_dict_entry_t *e = &p->arena->entries[ent_idx];
        e->key         = key;
        e->value_index = val_idx;

        if (!first_set) {
            first = ent_idx;
            first_set = 1;
        }
        count++;

        prev_key  = key;
        have_prev = 1;
    }

    if (p->pos >= p->len) {
        return BOWIE_ERR_FORMAT;
    }
    p->pos++; /* consume 'e' */

    size_t idx = 0u;
    bowie_error_t rc = arena_alloc_value(p->arena, &idx);
    if (rc != BOWIE_OK) {
        return rc;
    }

    bowie_bencode_value_t *v = &p->arena->values[idx];
    v->kind = BOWIE_BENCODE_DICT;
    v->u.dict.first = first;
    v->u.dict.count = count;

    *out_index = idx;
    return BOWIE_OK;
}

static bowie_error_t parse_value(parser_t *p, int depth,
                                 size_t *out_index)
{
    if (depth > BOWIE_BENCODE_MAX_DEPTH) {
        return BOWIE_ERR_FORMAT;
    }

    if (p->pos >= p->len) {
        return BOWIE_ERR_FORMAT;
    }

    uint8_t c = p->buf[p->pos];

    if (c == (uint8_t)'i') {
        p->pos++;
        int64_t value = 0;
        bowie_error_t rc = parse_integer(p, &value);
        if (rc != BOWIE_OK) {
            return rc;
        }

        size_t idx = 0u;
        rc = arena_alloc_value(p->arena, &idx);
        if (rc != BOWIE_OK) {
            return rc;
        }

        bowie_bencode_value_t *v = &p->arena->values[idx];
        v->kind = BOWIE_BENCODE_INT;
        v->u.int_val = value;

        *out_index = idx;
        return BOWIE_OK;
    }

    if (c == (uint8_t)'l') {
        p->pos++;
        return parse_list(p, depth, out_index);
    }

    if (c == (uint8_t)'d') {
        p->pos++;
        return parse_dict(p, depth, out_index);
    }

    if (is_digit(c)) {
        bowie_span_t s = { NULL, 0u };
        bowie_error_t rc = parse_string(p, &s);
        if (rc != BOWIE_OK) {
            return rc;
        }

        size_t idx = 0u;
        rc = arena_alloc_value(p->arena, &idx);
        if (rc != BOWIE_OK) {
            return rc;
        }

        bowie_bencode_value_t *v = &p->arena->values[idx];
        v->kind = BOWIE_BENCODE_STR;
        v->u.str_val = s;

        *out_index = idx;
        return BOWIE_OK;
    }

    return BOWIE_ERR_FORMAT;
}

/*
 * ============================================================================
 * DECODE — PUBLIC ENTRY POINT
 * ============================================================================
 */

bowie_error_t bowie_bencode_decode(
    bowie_span_t                    input,
    bowie_bencode_arena_t          *arena,
    const bowie_bencode_value_t   **out_root,
    int                             allow_lenient)
{
    if (arena == NULL || out_root == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }
    if (input.len > 0u && input.data == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }
    if (arena->values == NULL || arena->values_cap == 0u) {
        return BOWIE_ERR_INVAL;
    }
    if (arena->entries == NULL || arena->entries_cap == 0u) {
        return BOWIE_ERR_INVAL;
    }

    /*
     * Reset the arena's used counters and the lenient flag.
     * The caller's arrays are not cleared; only the counters
     * are reset.
     */
    arena->values_used  = 0u;
    arena->entries_used = 0u;
    arena->lenient_used = 0;

    parser_t p = {
        .buf           = input.data,
        .len           = input.len,
        .pos           = 0u,
        .allow_lenient = allow_lenient ? 1 : 0,
        .arena         = arena,
    };

    /*
     * The root value is allocated at index 0. The recursive
     * parser allocates the children. The root is written
     * after the parse, because the recursive parser writes
     * into the arena and may reallocate the array in a
     * future version. In this version the array never
     * moves, so the pointer is stable.
     */
    size_t root_idx = 0u;
    bowie_error_t rc = parse_value(&p, 0, &root_idx);
    if (rc != BOWIE_OK) {
        return rc;
    }

    /*
     * The whole input must be consumed. Trailing bytes are
     * an error.
     */
    if (p.pos != input.len) {
        return BOWIE_ERR_FORMAT;
    }

    *out_root = &arena->values[root_idx];
    return BOWIE_OK;
}

/*
 * ============================================================================
 * END OF FILE (PART 1 OF 3)
 * ============================================================================
 */
/*
 * ============================================================================
 * PART 2 — VALUE ACCESS
 * ============================================================================
 *
 * Helpers to read a decoded value. A caller that expects a
 * particular kind uses the matching accessor. An accessor that
 * is given the wrong kind returns an error and does not write
 * through the out pointer.
 *
 * Every accessor checks its pointer arguments. A NULL pointer
 * is an argument error, not a crash.
 *
 * The list and dict accessors return borrowed views. The
 * caller reads the children with list_at or dict_at.
 */

bowie_error_t bowie_bencode_get_int(
    const bowie_bencode_value_t *v, int64_t *out)
{
    if (v == NULL || out == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }
    if (v->kind != BOWIE_BENCODE_INT) {
        return BOWIE_ERR_TYPE;
    }
    *out = v->u.int_val;
    return BOWIE_OK;
}

bowie_error_t bowie_bencode_get_str(
    const bowie_bencode_value_t *v, bowie_span_t *out)
{
    if (v == NULL || out == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }
    if (v->kind != BOWIE_BENCODE_STR) {
        return BOWIE_ERR_TYPE;
    }
    *out = v->u.str_val;
    return BOWIE_OK;
}

bowie_error_t bowie_bencode_get_list(
    const bowie_bencode_value_t *v, bowie_bencode_list_t *out)
{
    if (v == NULL || out == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }
    if (v->kind != BOWIE_BENCODE_LIST) {
        return BOWIE_ERR_TYPE;
    }
    *out = v->u.list;
    return BOWIE_OK;
}

bowie_error_t bowie_bencode_get_dict(
    const bowie_bencode_value_t *v, bowie_bencode_dict_t *out)
{
    if (v == NULL || out == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }
    if (v->kind != BOWIE_BENCODE_DICT) {
        return BOWIE_ERR_TYPE;
    }
    *out = v->u.dict;
    return BOWIE_OK;
}

const bowie_bencode_value_t *bowie_bencode_list_at(
    const bowie_bencode_arena_t *arena,
    const bowie_bencode_value_t *list,
    size_t                       index)
{
    if (arena == NULL || list == NULL) {
        return NULL;
    }
    if (list->kind != BOWIE_BENCODE_LIST) {
        return NULL;
    }
    if (index >= list->u.list.count) {
        return NULL;
    }

    /*
     * The children are stored contiguously in the value
     * array, starting at list->u.list.first. The first
     * child is at first + 0, the second at first + 1, and
     * so on.
     *
     * The first index is the index of the first child.
     * The current child is at first + index.
     */
    size_t child_idx = list->u.list.first + index;
    if (child_idx >= arena->values_used) {
        return NULL;
    }
    return &arena->values[child_idx];
}

const bowie_bencode_dict_entry_t *bowie_bencode_dict_at(
    const bowie_bencode_arena_t *arena,
    const bowie_bencode_value_t *dict,
    size_t                       index)
{
    if (arena == NULL || dict == NULL) {
        return NULL;
    }
    if (dict->kind != BOWIE_BENCODE_DICT) {
        return NULL;
    }
    if (index >= dict->u.dict.count) {
        return NULL;
    }

    size_t ent_idx = dict->u.dict.first + index;
    if (ent_idx >= arena->entries_used) {
        return NULL;
    }
    return &arena->entries[ent_idx];
}

/*
 * ============================================================================
 * INTERNAL — KEY COMPARISON
 * ============================================================================
 *
 * Compare two byte strings in byte order. The comparison is
 * the same as the one the decoder uses for sorting: byte-wise,
 * shorter first when one is a prefix of the other.
 *
 * Returns:
 *   < 0  a comes before b
 *   = 0  a and b are equal
 *   > 0  a comes after b
 */

static int span_compare(bowie_span_t a, bowie_span_t b)
{
    size_t min = (a.len < b.len) ? a.len : b.len;

    if (min > 0u) {
        int cmp = memcmp(a.data, b.data, min);
        if (cmp != 0) {
            return cmp;
        }
    }
    if (a.len < b.len) {
        return -1;
    }
    if (a.len > b.len) {
        return 1;
    }
    return 0;
}

const bowie_bencode_value_t *bowie_bencode_dict_get(
    const bowie_bencode_arena_t *arena,
    const bowie_bencode_value_t *dict,
    bowie_span_t                 key)
{
    if (arena == NULL || dict == NULL) {
        return NULL;
    }
    if (dict->kind != BOWIE_BENCODE_DICT) {
        return NULL;
    }
    if (key.len > 0u && key.data == NULL) {
        return NULL;
    }

    /*
     * The decoder preserves the order of the keys as they
     * appear in the input. In strict mode the keys are
     * sorted, so a binary search is possible. In lenient
     * mode the keys may be unsorted, so a linear scan is
     * used.
     *
     * The linear scan is used unconditionally here. It is
     * O(n), but a DHT message has few keys, so the
     * difference does not matter. A future version can
     * switch to a binary search when the keys are known to
     * be sorted.
     */
    for (size_t i = 0u; i < dict->u.dict.count; i++) {
        const bowie_bencode_dict_entry_t *e =
            bowie_bencode_dict_at(arena, dict, i);
        if (e == NULL) {
            return NULL;
        }
        if (span_compare(e->key, key) == 0) {
            size_t vidx = e->value_index;
            if (vidx >= arena->values_used) {
                return NULL;
            }
            return &arena->values[vidx];
        }
    }

    return NULL;
}

/*
 * ============================================================================
 * END OF PART 2 — VALUE ACCESS
 * ============================================================================
 */
