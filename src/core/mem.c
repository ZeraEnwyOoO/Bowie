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
 * BOWIE — MEMORY IMPLEMENTATION
 * ============================================================================
 *
 * Allocation and memory operations.
 *
 * The implementation is thin. Each function is a small wrapper
 * over the platform allocator or the standard library, with a
 * defined behavior for zero-size and NULL-pointer inputs.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No custom allocator. The platform allocator is the only
 *     allocator.
 *   - No statistics. There is no counter of bytes allocated or
 *     of allocations in flight.
 *   - No I/O. Nothing here reads or writes a file, a socket, or
 *     a log.
 *   - No panic. An allocation failure returns NULL.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * The wrappers exist so that a single place owns the behavior
 * of zero-size allocation, NULL-pointer operations, and safe
 * size arithmetic. If any of those policies ever changes, the
 * change is here, not at every call site.
 *
 * The size arithmetic functions use the same overflow check
 * pattern:
 *
 *   - For a * b: check b != 0 && a > SIZE_MAX / b.
 *   - For a + b: check a > SIZE_MAX - b.
 *
 * The check is written before the operation, so the operation
 * itself never wraps. This is the standard C idiom.
 *
 * The allocation wrappers call the platform allocator directly.
 * They do not set errno, and they do not call any hook. A
 * caller that wants a typed error converts the NULL return at
 * the call site.
 *
 * The memory-operation wrappers call the standard library
 * directly. They guard against NULL pointers, which the
 * standard library does not. A NULL pointer with a non-zero
 * length is a caller bug in the standard library; here it is a
 * no-op, so a caller that forgets a length check does not
 * crash.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <stdlib.h>                  malloc, calloc, realloc, free
 *   <string.h>                  memset, memcpy, memmove, memcmp
 *   <stdint.h>                  SIZE_MAX
 *   "core/internal/mem.h"       the declarations
 * ============================================================================
 */

#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "core/internal/mem.h"

/*
 * ============================================================================
 * SIZE ARITHMETIC
 * ============================================================================
 */

int bowie_mem_size_mul(size_t a, size_t b, size_t *out)
{
    if (out == NULL) {
        return -1;
    }

    /*
     * Overflow check before the operation.
     *
     *   a * b overflows when b != 0 and a > SIZE_MAX / b.
     *
     * The check is on a, not on b, because division is exact
     * enough: if a <= SIZE_MAX / b, then a * b <= SIZE_MAX.
     */
    if (b != 0u && a > (SIZE_MAX / b)) {
        return -1;
    }

    *out = a * b;
    return 0;
}

int bowie_mem_size_add(size_t a, size_t b, size_t *out)
{
    if (out == NULL) {
        return -1;
    }

    /*
     * Overflow check before the operation.
     *
     *   a + b overflows when a > SIZE_MAX - b.
     */
    if (a > (SIZE_MAX - b)) {
        return -1;
    }

    *out = a + b;
    return 0;
}

int bowie_mem_size_add_mul(size_t a, size_t b, size_t c, size_t *out)
{
    if (out == NULL) {
        return -1;
    }

    size_t product = 0u;
    if (bowie_mem_size_mul(b, c, &product) != 0) {
        return -1;
    }

    size_t total = 0u;
    if (bowie_mem_size_add(a, product, &total) != 0) {
        return -1;
    }

    *out = total;
    return 0;
}

/*
 * ============================================================================
 * ALLOCATION
 * ============================================================================
 */

void *bowie_mem_alloc(size_t n)
{
    if (n == 0u) {
        return NULL;
    }
    return malloc(n);
}

void *bowie_mem_calloc(size_t n, size_t size)
{
    if (n == 0u || size == 0u) {
        return NULL;
    }

    /*
     * calloc checks its own multiplication for overflow on
     * every conforming platform. We do not duplicate the check;
     * calloc returns NULL on overflow.
     */
    return calloc(n, size);
}

void *bowie_mem_realloc(void *p, size_t n)
{
    if (n == 0u) {
        free(p);
        return NULL;
    }
    return realloc(p, n);
}

void bowie_mem_free(void *p)
{
    free(p);
}

/*
 * ============================================================================
 * MEMORY OPERATIONS
 * ============================================================================
 */

void bowie_mem_zero(void *p, size_t n)
{
    if (p == NULL || n == 0u) {
        return;
    }
    memset(p, 0, n);
}

void bowie_mem_copy(void *dst, const void *src, size_t n)
{
    if (dst == NULL || src == NULL || n == 0u) {
        return;
    }
    memcpy(dst, src, n);
}

void bowie_mem_move(void *dst, const void *src, size_t n)
{
    if (dst == NULL || src == NULL || n == 0u) {
        return;
    }
    memmove(dst, src, n);
}

int bowie_mem_compare(const void *a, const void *b, size_t n)
{
    if (a == NULL || b == NULL || n == 0u) {
        return 0;
    }
    return memcmp(a, b, n);
}

int bowie_mem_is_zero(const void *p, size_t n)
{
    if (p == NULL || n == 0u) {
        return 1;
    }

    const unsigned char *bytes = (const unsigned char *)p;
    for (size_t i = 0u; i < n; i++) {
        if (bytes[i] != 0u) {
            return 0;
        }
    }
    return 1;
}

/*
 * ============================================================================
 * END OF FILE
 * ============================================================================
 */
