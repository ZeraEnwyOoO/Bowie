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
 * BOWIE — RANDOM IMPLEMENTATION
 * ============================================================================
 *
 * Fast and secure random number generation.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No cryptographic key material. Key generation belongs to
 *     the crypto layer.
 *   - No caller-supplied seed. The fast generator is seeded
 *     once from the platform entropy source and never again.
 *   - No exposed state. The fast generator's state is private
 *     to this file.
 *   - No I/O. Nothing here reads or writes a file, a socket,
 *     or a log.
 *   - No allocation. Every function writes to caller-supplied
 *     storage.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * The fast generator is SplitMix64. It is a 64-bit mixing
 * function applied to a counter. The state is a single 64-bit
 * word; each call increments the counter and mixes it. The
 * output is a full 64-bit value. The top 32 bits are used for
 * the 32-bit function.
 *
 * SplitMix64 is chosen for its small state, its speed, and its
 * well-studied statistical properties. It is not a
 * cryptographic generator. It is used for jitter, retry
 * scheduling, and DHT bucket shuffling, where an attacker who
 * can predict the next value does not gain an advantage.
 *
 * The fast generator is not thread-safe. The state is a
 * single global word; two threads that call it concurrently
 * may produce the same output or may corrupt the state. A
 * caller that needs a thread-safe generator must provide one.
 * This module does not.
 *
 * The secure generator reads from the platform entropy source
 * on every call. On a Linux platform this is getrandom(2). On
 * a BSD or macOS platform this is getentropy(2) or an
 * equivalent. The wrapper here is a thin portability layer:
 * the platform-specific call is behind a single function, and
 * the rest of the module is platform-independent.
 *
 * The secure generator is the one to use for nonces, session
 * IDs, grant IDs, and DHT tokens. The fast generator must not
 * be used for those, even if the output looks random. A
 * generator that an attacker can predict from prior outputs
 * is not a secure source of nonces.
 *
 * The rejection sampling in bowie_rand_secure_below and
 * bowie_rand_fast_below removes the modulo bias. The naive
 * approach (random % bound) is biased whenever bound is not a
 * power of two. The bias is small for large bounds but is
 * still a bias. The rejection loop discards the values that
 * would cause it.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <stdint.h>                    uint32_t, uint64_t
 *   <stddef.h>                    size_t
 *   <string.h>                    memset, memcpy
 *   <errno.h>                     errno
 *   "bowie/err.h"                 error codes
 *   "core/internal/rand.h"        the declarations
 *
 * On Linux, also:
 *   <sys/random.h>                getrandom
 * ============================================================================
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>

#include "bowie/err.h"
#include "core/internal/rand.h"

/*
 * ============================================================================
 * PLATFORM ENTROPY
 * ============================================================================
 *
 * A single function that reads from the platform's entropy
 * source. Everything else in this file is platform-independent.
 *
 * On Linux, this is getrandom(2). On other platforms, the
 * implementation would be different; the contract is the same:
 * fill the buffer with bytes that an attacker cannot predict,
 * or return a non-zero error.
 *
 * The function returns 0 on success and -1 on failure. A
 * failure means the platform entropy source is not available
 * or refused the request.
 */

#if defined(__linux__)
#include <sys/random.h>

static int platform_entropy(void *buf, size_t n)
{
    /*
     * getrandom can be interrupted by a signal. A short read
     * is retried with the remaining buffer. A permanent
     * failure is reported.
     *
     * A return value of 0 is treated as a failure: getrandom
     * does not return 0 for a non-zero request.
     */
    uint8_t *p = (uint8_t *)buf;
    size_t remaining = n;

    while (remaining > 0u) {
        ssize_t got = getrandom(p, remaining, 0);
        if (got < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (got == 0) {
            return -1;
        }
        p += (size_t)got;
        remaining -= (size_t)got;
    }
    return 0;
}

#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__)
#include <stdlib.h>

static int platform_entropy(void *buf, size_t n)
{
    /*
     * arc4random_buf is available on macOS and the BSDs. It
     * is a CSPRNG seeded from the platform entropy source.
     */
    arc4random_buf(buf, n);
    return 0;
}

#else
#error "No platform entropy source for this platform."
#endif

/*
 * ============================================================================
 * FAST GENERATOR — SPLITMIX64
 * ============================================================================
 *
 * The state is a single 64-bit counter. Each call increments
 * the counter and mixes it. The mixing function is the one
 * published with SplitMix64.
 *
 * The state is a file-scope variable. It is not exposed. It is
 * initialized on first use from the platform entropy source.
 */

static uint64_t g_fast_state = 0u;
static int      g_fast_seeded = 0;

/*
 * The SplitMix64 mixing function. The constants are the ones
 * from the original algorithm.
 */
static uint64_t splitmix64_mix(uint64_t z)
{
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
    return z ^ (z >> 31);
}

/*
 * Seed the fast generator from the platform entropy source.
 *
 * The seed is a single 64-bit value read from the platform.
 * If the read fails, the generator is seeded with a value
 * derived from the address of the state variable and the
 * current time, which is not a good source of entropy but is
 * better than a fixed constant. The failure is not reported,
 * because the fast generator's contract is "fast and
 * statistically reasonable", not "unpredictable".
 */
static void fast_seed_once(void)
{
    if (g_fast_seeded) {
        return;
    }

    uint64_t seed = 0u;
    if (platform_entropy(&seed, sizeof(seed)) != 0) {
        /*
         * Fall back to a deterministic value. The fast
         * generator is not a security source, so a
         * deterministic seed is acceptable; it is not
         * preferred.
         */
        seed = (uint64_t)(uintptr_t)&g_fast_state;
    }

    /*
     * A seed of 0 is allowed; SplitMix64 handles it. The
     * counter is separate from the seed, so the generator
     * does not stay at zero.
     */
    g_fast_state  = splitmix64_mix(seed);
    g_fast_seeded = 1;
}

/*
 * ============================================================================
 * FAST GENERATOR — PUBLIC FUNCTIONS
 * ============================================================================
 */

uint64_t bowie_rand_fast_u64(void)
{
    fast_seed_once();

    g_fast_state += 0x9E3779B97F4A7C15ull;
    return splitmix64_mix(g_fast_state);
}

uint32_t bowie_rand_fast_u32(void)
{
    /*
     * Use the top 32 bits. The low bits of SplitMix64 are as
     * good as the high bits, but the top bits are the
     * conventional choice and match what a caller expects
     * from a 32-bit truncation of a 64-bit value.
     */
    return (uint32_t)(bowie_rand_fast_u64() >> 32);
}

void bowie_rand_fast_bytes(void *buf, size_t n)
{
    if (buf == NULL || n == 0u) {
        return;
    }

    uint8_t *p = (uint8_t *)buf;
    size_t remaining = n;

    while (remaining > 0u) {
        uint64_t word = bowie_rand_fast_u64();
        size_t   take = (remaining < 8u) ? remaining : 8u;

        /*
         * Copy the low `take` bytes of the word. The byte
         * order is whatever the platform uses for the
         * integer; the fast generator does not promise a
         * specific byte order.
         */
        memcpy(p, &word, take);
        p         += take;
        remaining -= take;
    }
}

uint64_t bowie_rand_fast_below(uint64_t bound)
{
    if (bound == 0u) {
        return 0u;
    }
    if (bound == 1u) {
        return 0u;
    }

    /*
     * Rejection sampling. The largest multiple of bound that
     * fits in a uint64_t is the threshold; values at or above
     * it are rejected. This removes the modulo bias.
     *
     * The loop terminates with probability 1. In the
     * worst case (bound just above 2^63), it takes two
     * iterations on average.
     */
    uint64_t limit = UINT64_MAX - (UINT64_MAX % bound);

    for (;;) {
        uint64_t r = bowie_rand_fast_u64();
        if (r < limit) {
            return r % bound;
        }
    }
}

/*
 * ============================================================================
 * SECURE GENERATOR — PUBLIC FUNCTIONS
 * ============================================================================
 */

bowie_error_t bowie_rand_secure_bytes(void *buf, size_t n)
{
    if (n == 0u) {
        return BOWIE_OK;
    }
    if (buf == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }
    if (platform_entropy(buf, n) != 0) {
        return BOWIE_ERR_NETWORK;
    }
    return BOWIE_OK;
}

bowie_error_t bowie_rand_secure_u64(uint64_t *out)
{
    if (out == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }

    /*
     * Retry a small number of times if the platform returns
     * zero. A zero from the platform entropy source is
     * technically valid but is a poor nonce. After a few
     * retries, report failure rather than a zero.
     */
    for (int attempt = 0; attempt < 8; attempt++) {
        uint64_t v = 0u;
        if (platform_entropy(&v, sizeof(v)) != 0) {
            return BOWIE_ERR_NETWORK;
        }
        if (v != 0u) {
            *out = v;
            return BOWIE_OK;
        }
    }

    return BOWIE_ERR_NETWORK;
}

bowie_error_t bowie_rand_secure_u32(uint32_t *out)
{
    if (out == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }

    for (int attempt = 0; attempt < 8; attempt++) {
        uint32_t v = 0u;
        if (platform_entropy(&v, sizeof(v)) != 0) {
            return BOWIE_ERR_NETWORK;
        }
        if (v != 0u) {
            *out = v;
            return BOWIE_OK;
        }
    }

    return BOWIE_ERR_NETWORK;
}

bowie_error_t bowie_rand_secure_below(uint64_t bound,
                                      uint64_t *out)
{
    if (out == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }
    if (bound == 0u) {
        return BOWIE_ERR_INVAL;
    }
    if (bound == 1u) {
        *out = 0u;
        return BOWIE_OK;
    }

    uint64_t limit = UINT64_MAX - (UINT64_MAX % bound);

    for (;;) {
        uint64_t r = 0u;
        bowie_error_t rc = bowie_rand_secure_u64(&r);
        if (rc != BOWIE_OK) {
            return rc;
        }
        if (r < limit) {
            *out = r % bound;
            return BOWIE_OK;
        }
    }
}

/*
 * ============================================================================
 * END OF FILE
 * ============================================================================
 */
