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
 * BOWIE — MEMORY (INTERNAL)
 * ============================================================================
 *
 * Allocation and memory operations used across the Bowie
 * library.
 *
 * This header is internal to the Bowie library. It is not part
 * of the public API and is not installed.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No custom allocator. Bowie does not expose an allocator
 *     hook. The platform allocator (malloc/calloc/realloc/free)
 *     is the only allocator.
 *   - No statistics. There is no counter of bytes allocated or
 *     of allocations in flight. A caller that needs that must
 *     build it on top.
 *   - No I/O. Nothing here reads or writes a file, a socket, or
 *     a log.
 *   - No panic. An allocation failure returns NULL. It does not
 *     abort the process.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * The allocation functions are thin wrappers over the platform
 * allocator. They exist for three reasons:
 *
 *   1. A single place to change if the allocator ever needs to
 *      change. A future allocator hook can be added here without
 *      touching every caller.
 *
 *   2. A defined zero-size behavior. malloc(0) is
 *      implementation-defined; bowie_mem_alloc(0) returns NULL
 *      on every platform.
 *
 *   3. Safe size arithmetic. bowie_mem_size_mul and
 *      bowie_mem_size_add detect overflow and report it,
 *      instead of silently wrapping. A caller that multiplies a
 *      count by a size before allocating must use them.
 *
 * The memory operations (zero, copy, move, compare) are thin
 * wrappers over the standard library. They exist so that a
 * caller can include one header instead of several, and so
 * that the NULL-pointer behavior is defined:
 *
 *   - bowie_mem_zero(NULL, n) is a no-op.
 *   - bowie_mem_copy(NULL, src, n) is a no-op.
 *   - bowie_mem_move(NULL, src, n) is a no-op.
 *   - bowie_mem_compare(NULL, NULL, 0) returns 0.
 *
 * A no-op is defined for a zero-length operation even when the
 * pointer is non-NULL, so that a caller never needs to guard a
 * call with a length check.
 *
 * The size arithmetic functions return 0 on success and -1 on
 * overflow. They do not set an errno and they do not call any
 * error hook. A caller that needs a typed error converts the
 * -1 at the call site.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <stddef.h>   size_t
 * ============================================================================
 */

#ifndef BOWIE_CORE_INTERNAL_MEM_H
#define BOWIE_CORE_INTERNAL_MEM_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ============================================================================
 * SIZE ARITHMETIC
 * ============================================================================
 *
 * Safe arithmetic on size_t values. Each function writes the
 * result through an out pointer and returns 0 on success or -1
 * on overflow.
 *
 * A NULL out pointer returns -1 without touching memory.
 */

/*
 * Compute a * b, store in *out.
 *
 * Returns 0 on success, -1 on overflow or if out is NULL.
 */
int bowie_mem_size_mul(size_t a, size_t b, size_t *out);

/*
 * Compute a + b, store in *out.
 *
 * Returns 0 on success, -1 on overflow or if out is NULL.
 */
int bowie_mem_size_add(size_t a, size_t b, size_t *out);

/*
 * Compute a + (b * c), store in *out.
 *
 * Returns 0 on success, -1 on overflow or if out is NULL.
 *
 * This is the common shape for an array allocation: a header
 * size plus a count times an element size.
 */
int bowie_mem_size_add_mul(size_t a, size_t b, size_t c, size_t *out);

/*
 * ============================================================================
 * ALLOCATION
 * ============================================================================
 *
 * Thin wrappers over the platform allocator.
 *
 * The zero-size behavior is defined:
 *
 *   - bowie_mem_alloc(0) returns NULL.
 *   - bowie_mem_calloc(0, n) returns NULL.
 *   - bowie_mem_calloc(n, 0) returns NULL.
 *
 * The realloc behavior is defined:
 *
 *   - bowie_mem_realloc(NULL, n) is bowie_mem_alloc(n).
 *   - bowie_mem_realloc(p, 0) frees p and returns NULL.
 *
 * The free behavior is defined:
 *
 *   - bowie_mem_free(NULL) is a no-op.
 */

/*
 * Allocate n bytes. Returns NULL on failure or if n is zero.
 *
 * The returned memory is not initialized.
 */
void *bowie_mem_alloc(size_t n);

/*
 * Allocate n * size bytes, zero them, and return a pointer to
 * the block.
 *
 * Returns NULL on failure if n or size is zero, or if the
 * multiplication overflows.
 */
void *bowie_mem_calloc(size_t n, size_t size);

/*
 * Resize a block.
 *
 * If p is NULL, behaves as bowie_mem_alloc(n).
 * If n is zero, frees p and returns NULL.
 *
 * Returns NULL on failure. The original block is not freed on
 * failure.
 */
void *bowie_mem_realloc(void *p, size_t n);

/*
 * Free a block. Passing NULL is a no-op.
 */
void bowie_mem_free(void *p);

/*
 * ============================================================================
 * MEMORY OPERATIONS
 * ============================================================================
 *
 * Thin wrappers over the standard library, with defined
 * NULL-pointer behavior.
 */

/*
 * Set n bytes of p to zero.
 *
 * A NULL p with n > 0 is a no-op (not undefined behavior). A
 * NULL p with n == 0 is a no-op.
 */
void bowie_mem_zero(void *p, size_t n);

/*
 * Copy n bytes from src to dst.
 *
 * The regions must not overlap; use bowie_mem_move for that.
 *
 * A NULL dst or src with n > 0 is a no-op.
 */
void bowie_mem_copy(void *dst, const void *src, size_t n);

/*
 * Move n bytes from src to dst. The regions may overlap.
 *
 * A NULL dst or src with n > 0 is a no-op.
 */
void bowie_mem_move(void *dst, const void *src, size_t n);

/*
 * Compare n bytes of a and b.
 *
 * Returns < 0, 0, or > 0 as for memcmp.
 *
 * Two NULL pointers with n == 0 return 0. A NULL pointer with
 * n > 0 returns 0 as well; a caller that cares about the
 * distinction must check the pointers itself.
 */
int bowie_mem_compare(const void *a, const void *b, size_t n);

/*
 * True when every byte of p is zero.
 *
 * A NULL p returns true. A p with n == 0 returns true.
 */
int bowie_mem_is_zero(const void *p, size_t n);

/*
 * ============================================================================
 * END OF INTERNAL MEMORY
 * ============================================================================
 */

#ifdef __cplusplus
}
#endif

#endif /* BOWIE_CORE_INTERNAL_MEM_H */
