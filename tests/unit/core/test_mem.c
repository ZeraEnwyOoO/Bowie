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
 * BOWIE — MEMORY TESTS
 * ============================================================================
 *
 * Unit tests for src/core/mem.c.
 *
 * Every public function declared in core/internal/mem.h is
 * covered here.
 *
 * The size arithmetic tests check the overflow boundary, not
 * just a normal value. The allocation tests check the defined
 * behavior for zero-size and NULL inputs, because that behavior
 * is the reason the wrappers exist.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <check.h>                       test framework
 *   <stdint.h>                      SIZE_MAX
 *   <string.h>                      memset, memcmp
 *   "core/internal/mem.h"           the unit under test
 * ============================================================================
 */

#include <check.h>
#include <stdint.h>
#include <string.h>

#include "core/internal/mem.h"

/*
 * ============================================================================
 * SIZE MULTIPLY
 * ============================================================================
 */

START_TEST(test_size_mul_null_out)
{
    ck_assert_int_eq(bowie_mem_size_mul(2u, 3u, NULL), -1);
}
END_TEST

START_TEST(test_size_mul_zero_by_anything)
{
    size_t out = 0xFFFFu;
    ck_assert_int_eq(bowie_mem_size_mul(0u, 100u, &out), 0);
    ck_assert_uint_eq(out, 0u);
}
END_TEST

START_TEST(test_size_mul_anything_by_zero)
{
    size_t out = 0xFFFFu;
    ck_assert_int_eq(bowie_mem_size_mul(100u, 0u, &out), 0);
    ck_assert_uint_eq(out, 0u);
}
END_TEST

START_TEST(test_size_mul_normal)
{
    size_t out = 0u;
    ck_assert_int_eq(bowie_mem_size_mul(6u, 7u, &out), 0);
    ck_assert_uint_eq(out, 42u);
}
END_TEST

START_TEST(test_size_mul_one)
{
    size_t out = 0u;
    ck_assert_int_eq(bowie_mem_size_mul(1u, 12345u, &out), 0);
    ck_assert_uint_eq(out, 12345u);
}
END_TEST

START_TEST(test_size_mul_overflow)
{
    size_t out = 0u;
    ck_assert_int_eq(bowie_mem_size_mul(SIZE_MAX, 2u, &out), -1);
}
END_TEST

START_TEST(test_size_mul_max_by_one_ok)
{
    size_t out = 0u;
    ck_assert_int_eq(bowie_mem_size_mul(SIZE_MAX, 1u, &out), 0);
    ck_assert_uint_eq(out, SIZE_MAX);
}
END_TEST

/*
 * ============================================================================
 * SIZE ADD
 * ============================================================================
 */

START_TEST(test_size_add_null_out)
{
    ck_assert_int_eq(bowie_mem_size_add(1u, 2u, NULL), -1);
}
END_TEST

START_TEST(test_size_add_zero)
{
    size_t out = 0xFFFFu;
    ck_assert_int_eq(bowie_mem_size_add(0u, 0u, &out), 0);
    ck_assert_uint_eq(out, 0u);
}
END_TEST

START_TEST(test_size_add_normal)
{
    size_t out = 0u;
    ck_assert_int_eq(bowie_mem_size_add(40u, 2u, &out), 0);
    ck_assert_uint_eq(out, 42u);
}
END_TEST

START_TEST(test_size_add_overflow)
{
    size_t out = 0u;
    ck_assert_int_eq(bowie_mem_size_add(SIZE_MAX, 1u, &out), -1);
}
END_TEST

START_TEST(test_size_add_max_plus_zero_ok)
{
    size_t out = 0u;
    ck_assert_int_eq(bowie_mem_size_add(SIZE_MAX, 0u, &out), 0);
    ck_assert_uint_eq(out, SIZE_MAX);
}
END_TEST

/*
 * ============================================================================
 * SIZE ADD MUL
 * ============================================================================
 */

START_TEST(test_size_add_mul_null_out)
{
    ck_assert_int_eq(bowie_mem_size_add_mul(1u, 2u, 3u, NULL), -1);
}
END_TEST

START_TEST(test_size_add_mul_normal)
{
    size_t out = 0u;
    /* 8 + (4 * 10) = 48 */
    ck_assert_int_eq(bowie_mem_size_add_mul(8u, 4u, 10u, &out), 0);
    ck_assert_uint_eq(out, 48u);
}
END_TEST

START_TEST(test_size_add_mul_zero_mul)
{
    size_t out = 0u;
    /* 8 + (0 * 10) = 8 */
    ck_assert_int_eq(bowie_mem_size_add_mul(8u, 0u, 10u, &out), 0);
    ck_assert_uint_eq(out, 8u);
}
END_TEST

START_TEST(test_size_add_mul_overflow_mul)
{
    size_t out = 0u;
    ck_assert_int_eq(
        bowie_mem_size_add_mul(0u, SIZE_MAX, 2u, &out), -1);
}
END_TEST

START_TEST(test_size_add_mul_overflow_add)
{
    size_t out = 0u;
    ck_assert_int_eq(
        bowie_mem_size_add_mul(SIZE_MAX, 1u, 1u, &out), -1);
}
END_TEST

/*
 * ============================================================================
 * ALLOC
 * ============================================================================
 */

START_TEST(test_alloc_zero_returns_null)
{
    ck_assert_ptr_null(bowie_mem_alloc(0u));
}
END_TEST

START_TEST(test_alloc_basic)
{
    void *p = bowie_mem_alloc(64u);
    ck_assert_ptr_nonnull(p);
    bowie_mem_free(p);
}
END_TEST

START_TEST(test_alloc_large)
{
    void *p = bowie_mem_alloc(4096u);
    ck_assert_ptr_nonnull(p);
    bowie_mem_free(p);
}
END_TEST

/*
 * ============================================================================
 * CALLOC
 * ============================================================================
 */

START_TEST(test_calloc_zero_n)
{
    ck_assert_ptr_null(bowie_mem_calloc(0u, 8u));
}
END_TEST

START_TEST(test_calloc_zero_size)
{
    ck_assert_ptr_null(bowie_mem_calloc(8u, 0u));
}
END_TEST

START_TEST(test_calloc_basic)
{
    void *p = bowie_mem_calloc(10u, 8u);
    ck_assert_ptr_nonnull(p);

    /* Every byte is zero. */
    const unsigned char *bytes = (const unsigned char *)p;
    for (size_t i = 0u; i < 80u; i++) {
        ck_assert_uint_eq(bytes[i], 0u);
    }

    bowie_mem_free(p);
}
END_TEST

/*
 * ============================================================================
 * REALLOC
 * ============================================================================
 */

START_TEST(test_realloc_null_is_alloc)
{
    void *p = bowie_mem_realloc(NULL, 32u);
    ck_assert_ptr_nonnull(p);
    bowie_mem_free(p);
}
END_TEST

START_TEST(test_realloc_zero_frees)
{
    void *p = bowie_mem_alloc(32u);
    ck_assert_ptr_nonnull(p);

    void *q = bowie_mem_realloc(p, 0u);
    ck_assert_ptr_null(q);
}
END_TEST

START_TEST(test_realloc_grow)
{
    void *p = bowie_mem_alloc(8u);
    ck_assert_ptr_nonnull(p);

    void *q = bowie_mem_realloc(p, 64u);
    ck_assert_ptr_nonnull(q);
    bowie_mem_free(q);
}
END_TEST

/*
 * ============================================================================
 * FREE
 * ============================================================================
 */

START_TEST(test_free_null_is_noop)
{
    bowie_mem_free(NULL);
}
END_TEST

/*
 * ============================================================================
 * ZERO
 * ============================================================================
 */

START_TEST(test_zero_basic)
{
    unsigned char buf[8];
    memset(buf, 0xFF, sizeof(buf));

    bowie_mem_zero(buf, sizeof(buf));

    for (size_t i = 0u; i < sizeof(buf); i++) {
        ck_assert_uint_eq(buf[i], 0u);
    }
}
END_TEST

START_TEST(test_zero_null_is_noop)
{
    bowie_mem_zero(NULL, 8u);
}
END_TEST

START_TEST(test_zero_len_zero_is_noop)
{
    unsigned char buf[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
    bowie_mem_zero(buf, 0u);
    ck_assert_uint_eq(buf[0], 1u);
}
END_TEST

/*
 * ============================================================================
 * COPY
 * ============================================================================
 */

START_TEST(test_copy_basic)
{
    const unsigned char src[4] = { 1, 2, 3, 4 };
    unsigned char dst[4] = { 0, 0, 0, 0 };

    bowie_mem_copy(dst, src, 4u);

    ck_assert_int_eq(memcmp(dst, src, 4u), 0);
}
END_TEST

START_TEST(test_copy_null_is_noop)
{
    unsigned char dst[4] = { 1, 2, 3, 4 };
    bowie_mem_copy(NULL, dst, 4u);
    bowie_mem_copy(dst, NULL, 4u);
    bowie_mem_copy(NULL, NULL, 4u);
    /* Nothing to check; the test passes if no crash. */
}
END_TEST

START_TEST(test_copy_zero_len)
{
    const unsigned char src[4] = { 1, 2, 3, 4 };
    unsigned char dst[4] = { 9, 9, 9, 9 };

    bowie_mem_copy(dst, src, 0u);

    ck_assert_uint_eq(dst[0], 9u);
}
END_TEST

/*
 * ============================================================================
 * MOVE
 * ============================================================================
 */

START_TEST(test_move_overlap_forward)
{
    /*
     * Move a block to the right within the same buffer. The
     * source and destination overlap; memmove handles it.
     */
    unsigned char buf[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };

    /* Copy buf[0..3] to buf[2..5]. */
    bowie_mem_move(buf + 2, buf, 4u);

    /* Expected: 1, 2, 1, 2, 3, 4, 7, 8 */
    ck_assert_uint_eq(buf[0], 1u);
    ck_assert_uint_eq(buf[1], 2u);
    ck_assert_uint_eq(buf[2], 1u);
    ck_assert_uint_eq(buf[3], 2u);
    ck_assert_uint_eq(buf[4], 3u);
    ck_assert_uint_eq(buf[5], 4u);
    ck_assert_uint_eq(buf[6], 7u);
    ck_assert_uint_eq(buf[7], 8u);
}
END_TEST

START_TEST(test_move_overlap_backward)
{
    /*
     * Move a block to the left within the same buffer.
     */
    unsigned char buf[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };

    /* Copy buf[4..7] to buf[0..3]. */
    bowie_mem_move(buf, buf + 4, 4u);

    /* Expected: 5, 6, 7, 8, 5, 6, 7, 8 */
    ck_assert_uint_eq(buf[0], 5u);
    ck_assert_uint_eq(buf[1], 6u);
    ck_assert_uint_eq(buf[2], 7u);
    ck_assert_uint_eq(buf[3], 8u);
    ck_assert_uint_eq(buf[4], 5u);
    ck_assert_uint_eq(buf[5], 6u);
    ck_assert_uint_eq(buf[6], 7u);
    ck_assert_uint_eq(buf[7], 8u);
}
END_TEST

START_TEST(test_move_null_is_noop)
{
    unsigned char dst[4] = { 1, 2, 3, 4 };
    bowie_mem_move(NULL, dst, 4u);
    bowie_mem_move(dst, NULL, 4u);
    bowie_mem_move(NULL, NULL, 4u);
}
END_TEST

/*
 * ============================================================================
 * COMPARE
 * ============================================================================
 */

START_TEST(test_compare_equal)
{
    const unsigned char a[4] = { 1, 2, 3, 4 };
    const unsigned char b[4] = { 1, 2, 3, 4 };
    ck_assert_int_eq(bowie_mem_compare(a, b, 4u), 0);
}
END_TEST

START_TEST(test_compare_different)
{
    const unsigned char a[4] = { 1, 2, 3, 4 };
    const unsigned char b[4] = { 1, 2, 3, 5 };
    ck_assert_int_lt(bowie_mem_compare(a, b, 4u), 0);
    ck_assert_int_gt(bowie_mem_compare(b, a, 4u), 0);
}
END_TEST

START_TEST(test_compare_zero_len)
{
    const unsigned char a[4] = { 1, 2, 3, 4 };
    const unsigned char b[4] = { 5, 6, 7, 8 };
    ck_assert_int_eq(bowie_mem_compare(a, b, 0u), 0);
}
END_TEST

START_TEST(test_compare_null)
{
    ck_assert_int_eq(bowie_mem_compare(NULL, NULL, 0u), 0);
    ck_assert_int_eq(bowie_mem_compare(NULL, NULL, 4u), 0);
}
END_TEST

/*
 * ============================================================================
 * IS ZERO
 * ============================================================================
 */

START_TEST(test_is_zero_all_zero)
{
    const unsigned char buf[4] = { 0, 0, 0, 0 };
    ck_assert(bowie_mem_is_zero(buf, 4u));
}
END_TEST

START_TEST(test_is_zero_not_zero)
{
    const unsigned char buf[4] = { 0, 0, 0, 1 };
    ck_assert(!bowie_mem_is_zero(buf, 4u));
}
END_TEST

START_TEST(test_is_zero_zero_len)
{
    const unsigned char buf[4] = { 1, 2, 3, 4 };
    ck_assert(bowie_mem_is_zero(buf, 0u));
}
END_TEST

START_TEST(test_is_zero_null)
{
    ck_assert(bowie_mem_is_zero(NULL, 0u));
    ck_assert(bowie_mem_is_zero(NULL, 4u));
}
END_TEST

/*
 * ============================================================================
 * SUITE
 * ============================================================================
 */

static Suite *mem_suite(void)
{
    Suite *s = suite_create("Mem");

    TCase *tc_mul = tcase_create("SizeMul");
    tcase_add_test(tc_mul, test_size_mul_null_out);
    tcase_add_test(tc_mul, test_size_mul_zero_by_anything);
    tcase_add_test(tc_mul, test_size_mul_anything_by_zero);
    tcase_add_test(tc_mul, test_size_mul_normal);
    tcase_add_test(tc_mul, test_size_mul_one);
    tcase_add_test(tc_mul, test_size_mul_overflow);
    tcase_add_test(tc_mul, test_size_mul_max_by_one_ok);
    suite_add_tcase(s, tc_mul);

    TCase *tc_add = tcase_create("SizeAdd");
    tcase_add_test(tc_add, test_size_add_null_out);
    tcase_add_test(tc_add, test_size_add_zero);
    tcase_add_test(tc_add, test_size_add_normal);
    tcase_add_test(tc_add, test_size_add_overflow);
    tcase_add_test(tc_add, test_size_add_max_plus_zero_ok);
    suite_add_tcase(s, tc_add);

    TCase *tc_am = tcase_create("SizeAddMul");
    tcase_add_test(tc_am, test_size_add_mul_null_out);
    tcase_add_test(tc_am, test_size_add_mul_normal);
    tcase_add_test(tc_am, test_size_add_mul_zero_mul);
    tcase_add_test(tc_am, test_size_add_mul_overflow_mul);
    tcase_add_test(tc_am, test_size_add_mul_overflow_add);
    suite_add_tcase(s, tc_am);

    TCase *tc_alloc = tcase_create("Alloc");
    tcase_add_test(tc_alloc, test_alloc_zero_returns_null);
    tcase_add_test(tc_alloc, test_alloc_basic);
    tcase_add_test(tc_alloc, test_alloc_large);
    suite_add_tcase(s, tc_alloc);

    TCase *tc_calloc = tcase_create("Calloc");
    tcase_add_test(tc_calloc, test_calloc_zero_n);
    tcase_add_test(tc_calloc, test_calloc_zero_size);
    tcase_add_test(tc_calloc, test_calloc_basic);
    suite_add_tcase(s, tc_calloc);

    TCase *tc_realloc = tcase_create("Realloc");
    tcase_add_test(tc_realloc, test_realloc_null_is_alloc);
    tcase_add_test(tc_realloc, test_realloc_zero_frees);
    tcase_add_test(tc_realloc, test_realloc_grow);
    suite_add_tcase(s, tc_realloc);

    TCase *tc_free = tcase_create("Free");
    tcase_add_test(tc_free, test_free_null_is_noop);
    suite_add_tcase(s, tc_free);

    TCase *tc_zero = tcase_create("Zero");
    tcase_add_test(tc_zero, test_zero_basic);
    tcase_add_test(tc_zero, test_zero_null_is_noop);
    tcase_add_test(tc_zero, test_zero_len_zero_is_noop);
    suite_add_tcase(s, tc_zero);

    TCase *tc_copy = tcase_create("Copy");
    tcase_add_test(tc_copy, test_copy_basic);
    tcase_add_test(tc_copy, test_copy_null_is_noop);
    tcase_add_test(tc_copy, test_copy_zero_len);
    suite_add_tcase(s, tc_copy);

    TCase *tc_move = tcase_create("Move");
    tcase_add_test(tc_move, test_move_overlap_forward);
    tcase_add_test(tc_move, test_move_overlap_backward);
    tcase_add_test(tc_move, test_move_null_is_noop);
    suite_add_tcase(s, tc_move);

    TCase *tc_cmp = tcase_create("Compare");
    tcase_add_test(tc_cmp, test_compare_equal);
    tcase_add_test(tc_cmp, test_compare_different);
    tcase_add_test(tc_cmp, test_compare_zero_len);
    tcase_add_test(tc_cmp, test_compare_null);
    suite_add_tcase(s, tc_cmp);

    TCase *tc_iz = tcase_create("IsZero");
    tcase_add_test(tc_iz, test_is_zero_all_zero);
    tcase_add_test(tc_iz, test_is_zero_not_zero);
    tcase_add_test(tc_iz, test_is_zero_zero_len);
    tcase_add_test(tc_iz, test_is_zero_null);
    suite_add_tcase(s, tc_iz);

    return s;
}

int main(void)
{
    Suite *s = mem_suite();
    SRunner *sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);

    int failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (failed == 0) ? 0 : 1;
}
