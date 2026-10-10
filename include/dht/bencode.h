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
 * BOWIE — BENCODE
 * ============================================================================
 *
 * Bencode encoding and decoding for the DHT layer.
 *
 * Bencode is the serialization format used by BitTorrent and by
 * the Mainline DHT. It has four types:
 *
 *   Integer       i42e
 *   Byte string   4:spam
 *   List          l...e
 *   Dictionary    d...e
 *
 * A dictionary key is always a byte string. Keys are sorted in
 * byte order.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No dynamic allocation in the decoder. Every function
 *     writes into a caller-supplied buffer.
 *   - No schema. The decoder produces a generic value tree.
 *     Interpreting the tree is the caller's job.
 *   - No streaming. Every function operates on a complete
 *     buffer.
 *   - No canonical form enforcement beyond the rules that
 *     Mainline requires. A caller that needs strict canonical
 *     form checks the result.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * The encoder and decoder are separate. A caller that only
 * needs to encode does not pay for the decoder, and vice
 * versa.
 *
 * The decoder has two modes:
 *
 *   - Strict mode. An error is returned for any deviation from
 *     the format: a leading zero in an integer, a negative
 *     zero, an unsorted dictionary key, a missing terminator.
 *
 *   - Lenient mode. The decoder accepts a small set of
 *     deviations that are known to occur in the wild, and
 *     reports them through an out-parameter. A caller that
 *     wants to be strict checks the parameter.
 *
 * The decoder does not allocate. The value tree is stored in a
 * caller-supplied arena: a single block of memory that the
 * decoder fills with nodes. The caller chooses the size of the
 * arena. A value tree that does not fit is reported as
 * BOWIE_ERR_TOO_SMALL.
 *
 * A byte string is a borrowed span. It points into the input
 * buffer. The caller must keep the input buffer alive for as
 * long as it uses the decoded value.
 *
 * The encoder is a single function that walks a value tree and
 * writes the encoded form. It follows the same no-allocation
 * rule: the caller supplies the output buffer.
 *
 * ----------------------------------------------------------------------------
 * Integer limits
 * ----------------------------------------------------------------------------
 *
 * Bencode integers are arbitrary precision in principle. The
 * Mainline DHT uses signed 64-bit integers in practice. This
 * module uses int64_t and rejects a value that does not fit.
 *
 * A leading zero is not allowed, except for the value 0 itself.
 * A negative zero is not allowed. These rules are part of the
 * format, not a choice.
 *
 * ----------------------------------------------------------------------------
 * Dictionary key order
 * ----------------------------------------------------------------------------
 *
 * A dictionary key is a byte string. Mainline requires the
 * keys to be sorted in byte order. This module enforces the
 * order in strict mode and reports the deviation in lenient
 * mode.
 *
 * The comparison is byte-wise, not locale-aware. Two keys are
 * compared by their raw bytes, shorter first if one is a
 * prefix of the other.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <stdint.h>                    int64_t, uint8_t
 *   <stddef.h>                    size_t
 *   "bowie/types.h"               bowie_span_t
 *   "bowie/err.h"                 error codes
 * ============================================================================
 */

#ifndef BOWIE_DHT_BENCODE_H
#define BOWIE_DHT_BENCODE_H

#include <stdint.h>
#include <stddef.h>

#include "bowie/types.h"
#include "bowie/err.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ============================================================================
 * VALUE TYPES
 * ============================================================================
 *
 * A decoded value is one of four kinds. The kind is stored in
 * a tag, and the payload is a union.
 *
 * A byte string and a dictionary key are borrowed spans. They
 * point into the input buffer.
 */

typedef enum bowie_bencode_kind {
    BOWIE_BENCODE_INT   = 1,
    BOWIE_BENCODE_STR   = 2,
    BOWIE_BENCODE_LIST  = 3,
    BOWIE_BENCODE_DICT  = 4,
} bowie_bencode_kind_t;

/*
 * A decoded value. The layout is:
 *
 *   kind        which member of the union is valid
 *   int_val     used when kind is INT
 *   str_val     used when kind is STR
 *   list        used when kind is LIST
 *   dict        used when kind is DICT
 *
 * The list and dict members are indices into the arena, not
 * pointers. The index of the first child is stored, and the
 * children are stored contiguously after it. The count is the
 * number of children.
 *
 * A list or dict with count == 0 has no children; the index
 * is unspecified.
 */

typedef struct bowie_bencode_value bowie_bencode_value_t;

typedef struct bowie_bencode_list {
    size_t first;   /* index of the first child */
    size_t count;   /* number of children */
} bowie_bencode_list_t;

typedef struct bowie_bencode_dict_entry {
    bowie_span_t key;                /* borrowed from input */
    size_t       value_index;        /* index into the arena */
} bowie_bencode_dict_entry_t;

typedef struct bowie_bencode_dict {
    size_t first;   /* index of the first entry */
    size_t count;   /* number of entries */
} bowie_bencode_dict_t;

struct bowie_bencode_value {
    bowie_bencode_kind_t kind;
    union {
        int64_t                   int_val;
        bowie_span_t              str_val;
        bowie_bencode_list_t      list;
        bowie_bencode_dict_t      dict;
    } u;
};

/*
 * ============================================================================
 * DECODE
 * ============================================================================
 */

/*
 * A decoded tree is stored in an arena. The arena is an array
 * of values. The root is the value at index 0. Children are
 * stored after the root, in the order they appear in the
 * input.
 *
 * The dict entries are stored in a separate array, because a
 * dict entry is a key-value pair, not a value. The dict's
 * "first" index is into the entry array, not the value array.
 *
 * A caller that wants to decode a message allocates two
 * arrays: one for values, one for dict entries. The sizes are
 * the caller's choice. A message that does not fit is
 * reported.
 */

typedef struct bowie_bencode_arena {
    bowie_bencode_value_t      *values;
    size_t                      values_cap;
    size_t                      values_used;

    bowie_bencode_dict_entry_t *entries;
    size_t                      entries_cap;
    size_t                      entries_used;

    /*
     * Set to 1 when the decoder accepted a deviation from
     * the strict format. A caller that wants strict behavior
     * checks this after the call.
     */
    int                         lenient_used;
} bowie_bencode_arena_t;

/*
 * Decode a bencoded buffer.
 *
 * The input is a borrowed span. The decoded byte strings and
 * dictionary keys point into it. The caller must keep the
 * input buffer alive for as long as it uses the decoded
 * value.
 *
 * On success, the root value is written through out_root, and
 * the arena's used counters are updated.
 *
 * The decoder is strict by default. If allow_lenient is
 * non-zero, the decoder accepts a small set of deviations
 * that are known to occur in the wild:
 *
 *   - An integer with a leading zero (other than "0" itself).
 *   - A negative zero.
 *   - A dictionary whose keys are not sorted.
 *
 * A deviation is not an error in lenient mode. The arena's
 * lenient_used flag is set to 1, and the decoded value is
 * returned.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NULL_ARG if any required pointer is NULL.
 * Returns BOWIE_ERR_FORMAT if the input is not valid bencode.
 * Returns BOWIE_ERR_TOO_SMALL if the arena is too small.
 * Returns BOWIE_ERR_TOO_LARGE if an integer does not fit in
 *   int64_t.
 */
bowie_error_t bowie_bencode_decode(
    bowie_span_t                    input,
    bowie_bencode_arena_t          *arena,
    const bowie_bencode_value_t   **out_root,
    int                             allow_lenient);

/*
 * ============================================================================
 * VALUE ACCESS
 * ============================================================================
 *
 * Helpers to read a decoded value. A caller that expects a
 * particular kind uses the matching accessor. An accessor that
 * is given the wrong kind returns an error and does not write
 * through the out pointer.
 */

/*
 * Read an integer.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NULL_ARG if v or out is NULL.
 * Returns BOWIE_ERR_TYPE if v is not an integer.
 */
bowie_error_t bowie_bencode_get_int(
    const bowie_bencode_value_t *v, int64_t *out);

/*
 * Read a byte string.
 *
 * The returned span is borrowed from the input buffer.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NULL_ARG if v or out is NULL.
 * Returns BOWIE_ERR_TYPE if v is not a byte string.
 */
bowie_error_t bowie_bencode_get_str(
    const bowie_bencode_value_t *v, bowie_span_t *out);

/*
 * Read a list.
 *
 * The returned list is a borrowed view. The caller reads the
 * children with bowie_bencode_list_at.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NULL_ARG if v or out is NULL.
 * Returns BOWIE_ERR_TYPE if v is not a list.
 */
bowie_error_t bowie_bencode_get_list(
    const bowie_bencode_value_t *v, bowie_bencode_list_t *out);

/*
 * Read a dictionary.
 *
 * The returned dict is a borrowed view. The caller reads the
 * entries with bowie_bencode_dict_at.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NULL_ARG if v or out is NULL.
 * Returns BOWIE_ERR_TYPE if v is not a dictionary.
 */
bowie_error_t bowie_bencode_get_dict(
    const bowie_bencode_value_t *v, bowie_bencode_dict_t *out);

/*
 * Return the child of a list at the given index.
 *
 * Returns a pointer to the child, or NULL if the index is out
 * of range.
 */
const bowie_bencode_value_t *bowie_bencode_list_at(
    const bowie_bencode_arena_t *arena,
    const bowie_bencode_value_t *list,
    size_t                       index);

/*
 * Return the entry of a dictionary at the given index.
 *
 * Returns a pointer to the entry, or NULL if the index is out
 * of range.
 */
const bowie_bencode_dict_entry_t *bowie_bencode_dict_at(
    const bowie_bencode_arena_t *arena,
    const bowie_bencode_value_t *dict,
    size_t                       index);

/*
 * Look up a key in a dictionary.
 *
 * The comparison is byte-wise. The key is not copied.
 *
 * Returns a pointer to the value, or NULL if the key is not
 * present.
 */
const bowie_bencode_value_t *bowie_bencode_dict_get(
    const bowie_bencode_arena_t *arena,
    const bowie_bencode_value_t *dict,
    bowie_span_t                 key);

/*
 * ============================================================================
 * ENCODE
 * ============================================================================
 */

/*
 * A writer is a caller-supplied output buffer plus a position.
 *
 * The buffer is filled from the start. A write that does not
 * fit is reported as BOWIE_ERR_TOO_SMALL. The position is
 * updated only on success.
 */

typedef struct bowie_bencode_writer {
    uint8_t *buf;
    size_t   cap;
    size_t   pos;
} bowie_bencode_writer_t;

/*
 * Initialize a writer over a caller-supplied buffer.
 *
 * Passing NULL for buf or a cap of 0 is a programming error;
 * the writer is left in a state that reports BOWIE_ERR_INVAL
 * on every write.
 */
void bowie_bencode_writer_init(bowie_bencode_writer_t *w,
                               uint8_t *buf, size_t cap);

/*
 * Encode an integer.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NULL_ARG if w is NULL.
 * Returns BOWIE_ERR_TOO_SMALL if the value does not fit.
 */
bowie_error_t bowie_bencode_write_int(bowie_bencode_writer_t *w,
                                      int64_t value);

/*
 * Encode a byte string.
 *
 * The input span is not copied; it is written as-is.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NULL_ARG if w is NULL or the span is
 *   malformed.
 * Returns BOWIE_ERR_TOO_SMALL if the value does not fit.
 */
bowie_error_t bowie_bencode_write_str(bowie_bencode_writer_t *w,
                                      bowie_span_t value);

/*
 * Begin a list.
 *
 * Writes the list opener. The caller writes the children and
 * then calls bowie_bencode_end_list.
 */
bowie_error_t bowie_bencode_begin_list(bowie_bencode_writer_t *w);

/*
 * End a list.
 *
 * Writes the list terminator.
 */
bowie_error_t bowie_bencode_end_list(bowie_bencode_writer_t *w);

/*
 * Begin a dictionary.
 *
 * Writes the dictionary opener. The caller writes the entries
 * with bowie_bencode_write_dict_entry and then calls
 * bowie_bencode_end_dict.
 *
 * The caller is responsible for writing the keys in sorted
 * order. This module does not sort them.
 */
bowie_error_t bowie_bencode_begin_dict(bowie_bencode_writer_t *w);

/*
 * End a dictionary.
 *
 * Writes the dictionary terminator.
 */
bowie_error_t bowie_bencode_end_dict(bowie_bencode_writer_t *w);

/*
 * Write one dictionary entry.
 *
 * The key is a byte string. The value is written by the
 * caller with one of the write functions.
 *
 * This function writes the key only; the caller writes the
 * value immediately after.
 */
bowie_error_t bowie_bencode_write_dict_key(
    bowie_bencode_writer_t *w, bowie_span_t key);

/*
 * Return the number of bytes written so far.
 */
size_t bowie_bencode_writer_pos(const bowie_bencode_writer_t *w);

/*
 * ============================================================================
 * END OF BENCODE
 * ============================================================================
 */

#ifdef __cplusplus
}
#endif

#endif /* BOWIE_DHT_BENCODE_H */
