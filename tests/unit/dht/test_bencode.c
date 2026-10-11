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
 * BOWIE — BENCODE TESTS
 * ============================================================================
 *
 * Unit tests for src/dht/bencode.c.
 *
 * The tests cover three groups:
 *
 *   - Decode: integer, string, list, dictionary, nesting,
 *     errors, and the lenient mode.
 *   - Access: the get and at functions.
 *   - Encode: integer, string, list, dictionary, and a
 *     round trip through decode.
 *
 * The test vectors are the ones in the BitTorrent bencode
 * specification, plus a few that exercise the error paths.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <check.h>                    test framework
 *   <string.h>                   memcmp
 *   "bowie/err.h"                error codes
 *   "dht/bencode.h"              the unit under test
 * ============================================================================
 */

#include <check.h>
#include <string.h>

#include "bowie/err.h"
#include "dht/bencode.h"

/*
 * ============================================================================
 * HELPERS
 * ============================================================================
 *
 * A decode test needs an arena. The arrays are file-scope so
 * that they are not on the stack; a large decode test can use
 * many values and entries. The arrays are reset by the decode
 * function, so a single set can be reused across tests.
 */

#define TEST_VALUE_CAP  64
#define TEST_ENTRY_CAP  32

static bowie_bencode_value_t      g_values[TEST_VALUE_CAP];
static bowie_bencode_dict_entry_t g_entries[TEST_ENTRY_CAP];

static bowie_bencode_arena_t make_arena(void)
{
    bowie_bencode_arena_t a;
    a.values       = g_values;
    a.values_cap   = TEST_VALUE_CAP;
    a.values_used  = 0u;
    a.entries      = g_entries;
    a.entries_cap  = TEST_ENTRY_CAP;
    a.entries_used = 0u;
    a.lenient_used = 0;
    return a;
}

static bowie_span_t span_of(const char *s)
{
    bowie_span_t sp;
    sp.data = (const uint8_t *)s;
    sp.len  = strlen(s);
    return sp;
}

/*
 * ============================================================================
 * DECODE — INTEGER
 * ============================================================================
 */

START_TEST(test_decode_int_zero)
{
    bowie_bencode_arena_t a = make_arena();
    const bowie_bencode_value_t *root = NULL;
    bowie_span_t in = span_of("i0e");

    ck_assert_int_eq(bowie_bencode_decode(in, &a, &root, 0),
                     BOWIE_OK);
    ck_assert_ptr_nonnull(root);

    int64_t v = 0;
    ck_assert_int_eq(bowie_bencode_get_int(root, &v), BOWIE_OK);
    ck_assert_int_eq(v, 0);
}
END_TEST

START_TEST(test_decode_int_positive)
{
    bowie_bencode_arena_t a = make_arena();
    const bowie_bencode_value_t *root = NULL;
    bowie_span_t in = span_of("i42e");

    ck_assert_int_eq(bowie_bencode_decode(in, &a, &root, 0),
                     BOWIE_OK);

    int64_t v = 0;
    ck_assert_int_eq(bowie_bencode_get_int(root, &v), BOWIE_OK);
    ck_assert_int_eq(v, 42);
}
END_TEST

START_TEST(test_decode_int_negative)
{
    bowie_bencode_arena_t a = make_arena();
    const bowie_bencode_value_t *root = NULL;
    bowie_span_t in = span_of("i-42e");

    ck_assert_int_eq(bowie_bencode_decode(in, &a, &root, 0),
                     BOWIE_OK);

    int64_t v = 0;
    ck_assert_int_eq(bowie_bencode_get_int(root, &v), BOWIE_OK);
    ck_assert_int_eq(v, -42);
}
END_TEST

START_TEST(test_decode_int_leading_zero_strict)
{
    bowie_bencode_arena_t a = make_arena();
    const bowie_bencode_value_t *root = NULL;
    bowie_span_t in = span_of("i042e");

    ck_assert_int_eq(bowie_bencode_decode(in, &a, &root, 0),
                     BOWIE_ERR_FORMAT);
}
END_TEST

START_TEST(test_decode_int_leading_zero_lenient)
{
    bowie_bencode_arena_t a = make_arena();
    const bowie_bencode_value_t *root = NULL;
    bowie_span_t in = span_of("i042e");

    ck_assert_int_eq(bowie_bencode_decode(in, &a, &root, 1),
                     BOWIE_OK);
    ck_assert_int_eq(a.lenient_used, 1);

    int64_t v = 0;
    ck_assert_int_eq(bowie_bencode_get_int(root, &v), BOWIE_OK);
    ck_assert_int_eq(v, 42);
}
END_TEST

START_TEST(test_decode_int_negative_zero_strict)
{
    bowie_bencode_arena_t a = make_arena();
    const bowie_bencode_value_t *root = NULL;
    bowie_span_t in = span_of("i-0e");

    ck_assert_int_eq(bowie_bencode_decode(in, &a, &root, 0),
                     BOWIE_ERR_FORMAT);
}
END_TEST

START_TEST(test_decode_int_negative_zero_lenient)
{
    bowie_bencode_arena_t a = make_arena();
    const bowie_bencode_value_t *root = NULL;
    bowie_span_t in = span_of("i-0e");

    ck_assert_int_eq(bowie_bencode_decode(in, &a, &root, 1),
                     BOWIE_OK);
    ck_assert_int_eq(a.lenient_used, 1);

    int64_t v = 0;
    ck_assert_int_eq(bowie_bencode_get_int(root, &v), BOWIE_OK);
    ck_assert_int_eq(v, 0);
}
END_TEST

START_TEST(test_decode_int_no_terminator)
{
    bowie_bencode_arena_t a = make_arena();
    const bowie_bencode_value_t *root = NULL;
    bowie_span_t in = span_of("i42");

    ck_assert_int_eq(bowie_bencode_decode(in, &a, &root, 0),
                     BOWIE_ERR_FORMAT);
}
END_TEST

START_TEST(test_decode_int_empty)
{
    bowie_bencode_arena_t a = make_arena();
    const bowie_bencode_value_t *root = NULL;
    bowie_span_t in = span_of("ie");

    ck_assert_int_eq(bowie_bencode_decode(in, &a, &root, 0),
                     BOWIE_ERR_FORMAT);
}
END_TEST

/*
 * ============================================================================
 * DECODE — STRING
 * ============================================================================
 */

START_TEST(test_decode_str_empty)
{
    bowie_bencode_arena_t a = make_arena();
    const bowie_bencode_value_t *root = NULL;
    bowie_span_t in = span_of("0:");

    ck_assert_int_eq(bowie_bencode_decode(in, &a, &root, 0),
                     BOWIE_OK);

    bowie_span_t s;
    ck_assert_int_eq(bowie_bencode_get_str(root, &s), BOWIE_OK);
    ck_assert_uint_eq(s.len, 0u);
}
END_TEST

START_TEST(test_decode_str_spam)
{
    bowie_bencode_arena_t a = make_arena();
    const bowie_bencode_value_t *root = NULL;
    bowie_span_t in = span_of("4:spam");

    ck_assert_int_eq(bowie_bencode_decode(in, &a, &root, 0),
                     BOWIE_OK);

    bowie_span_t s;
    ck_assert_int_eq(bowie_bencode_get_str(root, &s), BOWIE_OK);
    ck_assert_uint_eq(s.len, 4u);
    ck_assert_mem_eq(s.data, "spam", 4u);
}
END_TEST

START_TEST(test_decode_str_too_short)
{
    bowie_bencode_arena_t a = make_arena();
    const bowie_bencode_value_t *root = NULL;
    bowie_span_t in = span_of("5:spam");

    ck_assert_int_eq(bowie_bencode_decode(in, &a, &root, 0),
                     BOWIE_ERR_FORMAT);
}
END_TEST

START_TEST(test_decode_str_no_colon)
{
    bowie_bencode_arena_t a = make_arena();
    const bowie_bencode_value_t *root = NULL;
    bowie_span_t in = span_of("4spam");

    ck_assert_int_eq(bowie_bencode_decode(in, &a, &root, 0),
                     BOWIE_ERR_FORMAT);
}
END_TEST

/*
 * ============================================================================
 * DECODE — LIST
 * ============================================================================
 */

START_TEST(test_decode_list_empty)
{
    bowie_bencode_arena_t a = make_arena();
    const bowie_bencode_value_t *root = NULL;
    bowie_span_t in = span_of("le");

    ck_assert_int_eq(bowie_bencode_decode(in, &a, &root, 0),
                     BOWIE_OK);

    bowie_bencode_list_t l;
    ck_assert_int_eq(bowie_bencode_get_list(root, &l), BOWIE_OK);
    ck_assert_uint_eq(l.count, 0u);
}
END_TEST

START_TEST(test_decode_list_ints)
{
    bowie_bencode_arena_t a = make_arena();
    const bowie_bencode_value_t *root = NULL;
    bowie_span_t in = span_of("li1ei2ei3ee");

    ck_assert_int_eq(bowie_bencode_decode(in, &a, &root, 0),
                     BOWIE_OK);

    bowie_bencode_list_t l;
    ck_assert_int_eq(bowie_bencode_get_list(root, &l), BOWIE_OK);
    ck_assert_uint_eq(l.count, 3u);

    for (size_t i = 0u; i < 3u; i++) {
        const bowie_bencode_value_t *child =
            bowie_bencode_list_at(&a, root, i);
        ck_assert_ptr_nonnull(child);

        int64_t v = 0;
        ck_assert_int_eq(bowie_bencode_get_int(child, &v),
                         BOWIE_OK);
        ck_assert_int_eq(v, (int64_t)(i + 1u));
    }
}
END_TEST

START_TEST(test_decode_list_mixed)
{
    bowie_bencode_arena_t a = make_arena();
    const bowie_bencode_value_t *root = NULL;
    bowie_span_t in = span_of("li42e4:spame");

    ck_assert_int_eq(bowie_bencode_decode(in, &a, &root, 0),
                     BOWIE_OK);

    bowie_bencode_list_t l;
    ck_assert_int_eq(bowie_bencode_get_list(root, &l), BOWIE_OK);
    ck_assert_uint_eq(l.count, 2u);

    const bowie_bencode_value_t *c0 =
        bowie_bencode_list_at(&a, root, 0);
    ck_assert_ptr_nonnull(c0);
    int64_t v = 0;
    ck_assert_int_eq(bowie_bencode_get_int(c0, &v), BOWIE_OK);
    ck_assert_int_eq(v, 42);

    const bowie_bencode_value_t *c1 =
        bowie_bencode_list_at(&a, root, 1);
    ck_assert_ptr_nonnull(c1);
    bowie_span_t s;
    ck_assert_int_eq(bowie_bencode_get_str(c1, &s), BOWIE_OK);
    ck_assert_uint_eq(s.len, 4u);
    ck_assert_mem_eq(s.data, "spam", 4u);
}
END_TEST

START_TEST(test_decode_list_missing_terminator)
{
    bowie_bencode_arena_t a = make_arena();
    const bowie_bencode_value_t *root = NULL;
    bowie_span_t in = span_of("li1e");

    ck_assert_int_eq(bowie_bencode_decode(in, &a, &root, 0),
                     BOWIE_ERR_FORMAT);
}
END_TEST

/*
 * ============================================================================
 * DECODE — DICTIONARY
 * ============================================================================
 */

START_TEST(test_decode_dict_empty)
{
    bowie_bencode_arena_t a = make_arena();
    const bowie_bencode_value_t *root = NULL;
    bowie_span_t in = span_of("de");

    ck_assert_int_eq(bowie_bencode_decode(in, &a, &root, 0),
                     BOWIE_OK);

    bowie_bencode_dict_t d;
    ck_assert_int_eq(bowie_bencode_get_dict(root, &d), BOWIE_OK);
    ck_assert_uint_eq(d.count, 0u);
}
END_TEST

START_TEST(test_decode_dict_single)
{
    bowie_bencode_arena_t a = make_arena();
    const bowie_bencode_value_t *root = NULL;
    bowie_span_t in = span_of("d1:ai42ee");

    ck_assert_int_eq(bowie_bencode_decode(in, &a, &root, 0),
                     BOWIE_OK);

    bowie_bencode_dict_t d;
    ck_assert_int_eq(bowie_bencode_get_dict(root, &d), BOWIE_OK);
    ck_assert_uint_eq(d.count, 1u);

    const bowie_bencode_value_t *v =
        bowie_bencode_dict_get(&a, root, span_of("a"));
    ck_assert_ptr_nonnull(v);

    int64_t i = 0;
    ck_assert_int_eq(bowie_bencode_get_int(v, &i), BOWIE_OK);
    ck_assert_int_eq(i, 42);
}
END_TEST

START_TEST(test_decode_dict_sorted)
{
    bowie_bencode_arena_t a = make_arena();
    const bowie_bencode_value_t *root = NULL;
    bowie_span_t in = span_of("d1:ai1e1:bi2ee");

    ck_assert_int_eq(bowie_bencode_decode(in, &a, &root, 0),
                     BOWIE_OK);

    const bowie_bencode_value_t *va =
        bowie_bencode_dict_get(&a, root, span_of("a"));
    ck_assert_ptr_nonnull(va);
    int64_t i = 0;
    ck_assert_int_eq(bowie_bencode_get_int(va, &i), BOWIE_OK);
    ck_assert_int_eq(i, 1);

    const bowie_bencode_value_t *vb =
        bowie_bencode_dict_get(&a, root, span_of("b"));
    ck_assert_ptr_nonnull(vb);
    ck_assert_int_eq(bowie_bencode_get_int(vb, &i), BOWIE_OK);
    ck_assert_int_eq(i, 2);
}
END_TEST

START_TEST(test_decode_dict_unsorted_strict)
{
    bowie_bencode_arena_t a = make_arena();
    const bowie_bencode_value_t *root = NULL;
    bowie_span_t in = span_of("d1:bi2e1:ai1ee");

    ck_assert_int_eq(bowie_bencode_decode(in, &a, &root, 0),
                     BOWIE_ERR_FORMAT);
}
END_TEST

START_TEST(test_decode_dict_unsorted_lenient)
{
    bowie_bencode_arena_t a = make_arena();
    const bowie_bencode_value_t *root = NULL;
    bowie_span_t in = span_of("d1:bi2e1:ai1ee");

    ck_assert_int_eq(bowie_bencode_decode(in, &a, &root, 1),
                     BOWIE_OK);
    ck_assert_int_eq(a.lenient_used, 1);
}
END_TEST

START_TEST(test_decode_dict_missing_value)
{
    bowie_bencode_arena_t a = make_arena();
    const bowie_bencode_value_t *root = NULL;
    bowie_span_t in = span_of("d1:ae");

    ck_assert_int_eq(bowie_bencode_decode(in, &a, &root, 0),
                     BOWIE_ERR_FORMAT);
}
END_TEST

/*
 * ============================================================================
 * DECODE — NESTING
 * ============================================================================
 */

START_TEST(test_decode_nested_list_in_dict)
{
    bowie_bencode_arena_t a = make_arena();
    const bowie_bencode_value_t *root = NULL;
    bowie_span_t in = span_of("d1:ali1ei2eee");

    ck_assert_int_eq(bowie_bencode_decode(in, &a, &root, 0),
                     BOWIE_OK);

    const bowie_bencode_value_t *lst =
        bowie_bencode_dict_get(&a, root, span_of("a"));
    ck_assert_ptr_nonnull(lst);

    bowie_bencode_list_t l;
    ck_assert_int_eq(bowie_bencode_get_list(lst, &l), BOWIE_OK);
    ck_assert_uint_eq(l.count, 2u);
}
END_TEST

START_TEST(test_decode_nested_dict_in_list)
{
    bowie_bencode_arena_t a = make_arena();
    const bowie_bencode_value_t *root = NULL;
    bowie_span_t in = span_of("ld1:ai1eee");

    ck_assert_int_eq(bowie_bencode_decode(in, &a, &root, 0),
                     BOWIE_OK);

    const bowie_bencode_value_t *d =
        bowie_bencode_list_at(&a, root, 0);
    ck_assert_ptr_nonnull(d);

    bowie_bencode_dict_t dd;
    ck_assert_int_eq(bowie_bencode_get_dict(d, &dd), BOWIE_OK);
    ck_assert_uint_eq(dd.count, 1u);
}
END_TEST

/*
 * ============================================================================
 * DECODE — ERRORS
 * ============================================================================
 */

START_TEST(test_decode_null_arena)
{
    const bowie_bencode_value_t *root = NULL;
    bowie_span_t in = span_of("i0e");

    ck_assert_int_eq(bowie_bencode_decode(in, NULL, &root, 0),
                     BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_decode_null_out)
{
    bowie_bencode_arena_t a = make_arena();
    bowie_span_t in = span_of("i0e");

    ck_assert_int_eq(bowie_bencode_decode(in, &a, NULL, 0),
                     BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_decode_empty_input)
{
    bowie_bencode_arena_t a = make_arena();
    const bowie_bencode_value_t *root = NULL;
    bowie_span_t in = { NULL, 0u };

    ck_assert_int_eq(bowie_bencode_decode(in, &a, &root, 0),
                     BOWIE_ERR_FORMAT);
}
END_TEST

START_TEST(test_decode_trailing_bytes)
{
    bowie_bencode_arena_t a = make_arena();
    const bowie_bencode_value_t *root = NULL;
    bowie_span_t in = span_of("i0ejunk");

    ck_assert_int_eq(bowie_bencode_decode(in, &a, &root, 0),
                     BOWIE_ERR_FORMAT);
}
END_TEST

START_TEST(test_decode_garbage)
{
    bowie_bencode_arena_t a = make_arena();
    const bowie_bencode_value_t *root = NULL;
    bowie_span_t in = span_of("xyz");

    ck_assert_int_eq(bowie_bencode_decode(in, &a, &root, 0),
                     BOWIE_ERR_FORMAT);
}
END_TEST

START_TEST(test_decode_arena_too_small)
{
    /*
     * A tiny arena. The decoder needs a value for the root.
     * The arena can hold zero values, so the decode fails.
     */
    bowie_bencode_value_t small_values[0];
    bowie_bencode_dict_entry_t small_entries[1];

    bowie_bencode_arena_t a;
    a.values       = small_values;
    a.values_cap   = 0u;
    a.values_used  = 0u;
    a.entries      = small_entries;
    a.entries_cap  = 1u;
    a.entries_used = 0u;
    a.lenient_used = 0;

    const bowie_bencode_value_t *root = NULL;
    bowie_span_t in = span_of("i0e");

    ck_assert_int_eq(bowie_bencode_decode(in, &a, &root, 0),
                     BOWIE_ERR_INVAL);
}
END_TEST

/*
 * ============================================================================
 * ACCESS — WRONG KIND
 * ============================================================================
 */

START_TEST(test_get_int_wrong_kind)
{
    bowie_bencode_arena_t a = make_arena();
    const bowie_bencode_value_t *root = NULL;
    bowie_span_t in = span_of("4:spam");

    ck_assert_int_eq(bowie_bencode_decode(in, &a, &root, 0),
                     BOWIE_OK);

    int64_t v = 0;
    ck_assert_int_eq(bowie_bencode_get_int(root, &v),
                     BOWIE_ERR_TYPE);
}
END_TEST

START_TEST(test_get_str_wrong_kind)
{
    bowie_bencode_arena_t a = make_arena();
    const bowie_bencode_value_t *root = NULL;
    bowie_span_t in = span_of("i42e");

    ck_assert_int_eq(bowie_bencode_decode(in, &a, &root, 0),
                     BOWIE_OK);

    bowie_span_t s;
    ck_assert_int_eq(bowie_bencode_get_str(root, &s),
                     BOWIE_ERR_TYPE);
}
END_TEST

START_TEST(test_get_list_wrong_kind)
{
    bowie_bencode_arena_t a = make_arena();
    const bowie_bencode_value_t *root = NULL;
    bowie_span_t in = span_of("i42e");

    ck_assert_int_eq(bowie_bencode_decode(in, &a, &root, 0),
                     BOWIE_OK);

    bowie_bencode_list_t l;
    ck_assert_int_eq(bowie_bencode_get_list(root, &l),
                     BOWIE_ERR_TYPE);
}
END_TEST

START_TEST(test_get_dict_wrong_kind)
{
    bowie_bencode_arena_t a = make_arena();
    const bowie_bencode_value_t *root = NULL;
    bowie_span_t in = span_of("i42e");

    ck_assert_int_eq(bowie_bencode_decode(in, &a, &root, 0),
                     BOWIE_OK);

    bowie_bencode_dict_t d;
    ck_assert_int_eq(bowie_bencode_get_dict(root, &d),
                     BOWIE_ERR_TYPE);
}
END_TEST

START_TEST(test_get_int_null)
{
    int64_t v = 0;
    ck_assert_int_eq(bowie_bencode_get_int(NULL, &v),
                     BOWIE_ERR_NULL_ARG);
}
END_TEST

START_TEST(test_get_int_null_out)
{
    bowie_bencode_arena_t a = make_arena();
    const bowie_bencode_value_t *root = NULL;
    bowie_span_t in = span_of("i42e");

    ck_assert_int_eq(bowie_bencode_decode(in, &a, &root, 0),
                     BOWIE_OK);

    ck_assert_int_eq(bowie_bencode_get_int(root, NULL),
                     BOWIE_ERR_NULL_ARG);
}
END_TEST

/*
 * ============================================================================
 * ACCESS — LIST_AT / DICT_AT / DICT_GET
 * ============================================================================
 */

START_TEST(test_list_at_out_of_range)
{
    bowie_bencode_arena_t a = make_arena();
    const bowie_bencode_value_t *root = NULL;
    bowie_span_t in = span_of("li1ee");

    ck_assert_int_eq(bowie_bencode_decode(in, &a, &root, 0),
                     BOWIE_OK);

    ck_assert_ptr_null(bowie_bencode_list_at(&a, root, 5u));
}
END_TEST

START_TEST(test_list_at_wrong_kind)
{
    bowie_bencode_arena_t a = make_arena();
    const bowie_bencode_value_t *root = NULL;
    bowie_span_t in = span_of("i42e");

    ck_assert_int_eq(bowie_bencode_decode(in, &a, &root, 0),
                     BOWIE_OK);

    ck_assert_ptr_null(bowie_bencode_list_at(&a, root, 0u));
}
END_TEST

START_TEST(test_list_at_null)
{
    ck_assert_ptr_null(bowie_bencode_list_at(NULL, NULL, 0u));
}
END_TEST

START_TEST(test_dict_at_out_of_range)
{
    bowie_bencode_arena_t a = make_arena();
    const bowie_bencode_value_t *root = NULL;
    bowie_span_t in = span_of("d1:ai1ee");

    ck_assert_int_eq(bowie_bencode_decode(in, &a, &root, 0),
                     BOWIE_OK);

    ck_assert_ptr_null(bowie_bencode_dict_at(&a, root, 5u));
}
END_TEST

START_TEST(test_dict_at_wrong_kind)
{
    bowie_bencode_arena_t a = make_arena();
    const bowie_bencode_value_t *root = NULL;
    bowie_span_t in = span_of("i42e");

    ck_assert_int_eq(bowie_bencode_decode(in, &a, &root, 0),
                     BOWIE_OK);

    ck_assert_ptr_null(bowie_bencode_dict_at(&a, root, 0u));
}
END_TEST

START_TEST(test_dict_get_missing)
{
    bowie_bencode_arena_t a = make_arena();
    const bowie_bencode_value_t *root = NULL;
    bowie_span_t in = span_of("d1:ai1ee");

    ck_assert_int_eq(bowie_bencode_decode(in, &a, &root, 0),
                     BOWIE_OK);

    ck_assert_ptr_null(
        bowie_bencode_dict_get(&a, root, span_of("missing")));
}
END_TEST

START_TEST(test_dict_get_null)
{
    bowie_span_t key = span_of("a");
    ck_assert_ptr_null(bowie_bencode_dict_get(NULL, NULL, key));
}
END_TEST

/*
 * ============================================================================
 * ENCODE — INTEGER
 * ============================================================================
 */

START_TEST(test_encode_int_zero)
{
    uint8_t buf[16];
    bowie_bencode_writer_t w;
    bowie_bencode_writer_init(&w, buf, sizeof(buf));

    ck_assert_int_eq(bowie_bencode_write_int(&w, 0), BOWIE_OK);

    ck_assert_uint_eq(w.pos, 3u);
    ck_assert_mem_eq(buf, "i0e", 3u);
}
END_TEST

START_TEST(test_encode_int_positive)
{
    uint8_t buf[16];
    bowie_bencode_writer_t w;
    bowie_bencode_writer_init(&w, buf, sizeof(buf));

    ck_assert_int_eq(bowie_bencode_write_int(&w, 42), BOWIE_OK);

    ck_assert_mem_eq(buf, "i42e", 4u);
}
END_TEST

START_TEST(test_encode_int_negative)
{
    uint8_t buf[16];
    bowie_bencode_writer_t w;
    bowie_bencode_writer_init(&w, buf, sizeof(buf));

    ck_assert_int_eq(bowie_bencode_write_int(&w, -42), BOWIE_OK);

    ck_assert_mem_eq(buf, "i-42e", 5u);
}
END_TEST

START_TEST(test_encode_int_too_small)
{
    uint8_t buf[2];
    bowie_bencode_writer_t w;
    bowie_bencode_writer_init(&w, buf, sizeof(buf));

    ck_assert_int_eq(bowie_bencode_write_int(&w, 42),
                     BOWIE_ERR_TOO_SMALL);
    ck_assert_uint_eq(w.pos, 0u);
}
END_TEST

/*
 * ============================================================================
 * ENCODE — STRING
 * ============================================================================
 */

START_TEST(test_encode_str_empty)
{
    uint8_t buf[16];
    bowie_bencode_writer_t w;
    bowie_bencode_writer_init(&w, buf, sizeof(buf));

    bowie_span_t s = { NULL, 0u };
    ck_assert_int_eq(bowie_bencode_write_str(&w, s), BOWIE_OK);

    ck_assert_mem_eq(buf, "0:", 2u);
}
END_TEST

START_TEST(test_encode_str_spam)
{
    uint8_t buf[16];
    bowie_bencode_writer_t w;
    bowie_bencode_writer_init(&w, buf, sizeof(buf));

    ck_assert_int_eq(bowie_bencode_write_str(&w, span_of("spam")),
                     BOWIE_OK);

    ck_assert_mem_eq(buf, "4:spam", 6u);
}
END_TEST

START_TEST(test_encode_str_too_small)
{
    uint8_t buf[4];
    bowie_bencode_writer_t w;
    bowie_bencode_writer_init(&w, buf, sizeof(buf));

    ck_assert_int_eq(
        bowie_bencode_write_str(&w, span_of("hello")),
        BOWIE_ERR_TOO_SMALL);
}
END_TEST

/*
 * ============================================================================
 * ENCODE — LIST / DICT
 * ============================================================================
 */

START_TEST(test_encode_list_empty)
{
    uint8_t buf[16];
    bowie_bencode_writer_t w;
    bowie_bencode_writer_init(&w, buf, sizeof(buf));

    ck_assert_int_eq(bowie_bencode_begin_list(&w), BOWIE_OK);
    ck_assert_int_eq(bowie_bencode_end_list(&w), BOWIE_OK);

    ck_assert_mem_eq(buf, "le", 2u);
}
END_TEST

START_TEST(test_encode_list_ints)
{
    uint8_t buf[32];
    bowie_bencode_writer_t w;
    bowie_bencode_writer_init(&w, buf, sizeof(buf));

    ck_assert_int_eq(bowie_bencode_begin_list(&w), BOWIE_OK);
    ck_assert_int_eq(bowie_bencode_write_int(&w, 1), BOWIE_OK);
    ck_assert_int_eq(bowie_bencode_write_int(&w, 2), BOWIE_OK);
    ck_assert_int_eq(bowie_bencode_end_list(&w), BOWIE_OK);

    ck_assert_mem_eq(buf, "li1ei2ee", 8u);
}
END_TEST

START_TEST(test_encode_dict_empty)
{
    uint8_t buf[16];
    bowie_bencode_writer_t w;
    bowie_bencode_writer_init(&w, buf, sizeof(buf));

    ck_assert_int_eq(bowie_bencode_begin_dict(&w), BOWIE_OK);
    ck_assert_int_eq(bowie_bencode_end_dict(&w), BOWIE_OK);

    ck_assert_mem_eq(buf, "de", 2u);
}
END_TEST

START_TEST(test_encode_dict_single)
{
    uint8_t buf[32];
    bowie_bencode_writer_t w;
    bowie_bencode_writer_init(&w, buf, sizeof(buf));

    ck_assert_int_eq(bowie_bencode_begin_dict(&w), BOWIE_OK);
    ck_assert_int_eq(
        bowie_bencode_write_dict_key(&w, span_of("a")), BOWIE_OK);
    ck_assert_int_eq(bowie_bencode_write_int(&w, 42), BOWIE_OK);
    ck_assert_int_eq(bowie_bencode_end_dict(&w), BOWIE_OK);

    ck_assert_mem_eq(buf, "d1:ai42ee", 9u);
}
END_TEST

/*
 * ============================================================================
 * ROUND TRIP
 * ============================================================================
 */

START_TEST(test_round_trip_dict)
{
    /*
     * Encode a dictionary, then decode the result and check
     * that the value is the same.
     */
    uint8_t buf[64];
    bowie_bencode_writer_t w;
    bowie_bencode_writer_init(&w, buf, sizeof(buf));

    ck_assert_int_eq(bowie_bencode_begin_dict(&w), BOWIE_OK);
    ck_assert_int_eq(
        bowie_bencode_write_dict_key(&w, span_of("a")), BOWIE_OK);
    ck_assert_int_eq(bowie_bencode_write_int(&w, 1), BOWIE_OK);
    ck_assert_int_eq(
        bowie_bencode_write_dict_key(&w, span_of("b")), BOWIE_OK);
    ck_assert_int_eq(
        bowie_bencode_write_str(&w, span_of("hello")), BOWIE_OK);
    ck_assert_int_eq(bowie_bencode_end_dict(&w), BOWIE_OK);

    bowie_span_t encoded;
    encoded.data = buf;
    encoded.len  = w.pos;

    bowie_bencode_arena_t a = make_arena();
    const bowie_bencode_value_t *root = NULL;
    ck_assert_int_eq(
        bowie_bencode_decode(encoded, &a, &root, 0), BOWIE_OK);

    const bowie_bencode_value_t *va =
        bowie_bencode_dict_get(&a, root, span_of("a"));
    ck_assert_ptr_nonnull(va);
    int64_t i = 0;
    ck_assert_int_eq(bowie_bencode_get_int(va, &i), BOWIE_OK);
    ck_assert_int_eq(i, 1);

    const bowie_bencode_value_t *vb =
        bowie_bencode_dict_get(&a, root, span_of("b"));
    ck_assert_ptr_nonnull(vb);
    bowie_span_t s;
    ck_assert_int_eq(bowie_bencode_get_str(vb, &s), BOWIE_OK);
    ck_assert_uint_eq(s.len, 5u);
    ck_assert_mem_eq(s.data, "hello", 5u);
}
END_TEST

/*
 * ============================================================================
 * SUITE
 * ============================================================================
 */

static Suite *bencode_suite(void)
{
    Suite *s = suite_create("Bencode");

    TCase *tc_int = tcase_create("DecodeInt");
    tcase_add_test(tc_int, test_decode_int_zero);
    tcase_add_test(tc_int, test_decode_int_positive);
    tcase_add_test(tc_int, test_decode_int_negative);
    tcase_add_test(tc_int, test_decode_int_leading_zero_strict);
    tcase_add_test(tc_int, test
