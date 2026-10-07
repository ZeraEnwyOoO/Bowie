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
 * BOWIE — RANDOM (INTERNAL)
 * ============================================================================
 *
 * Random number generation for the Bowie library.
 *
 * This header is internal to the Bowie library. It is not part
 * of the public API and is not installed.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No cryptographic key material. This module does not
 *     generate keys. Key generation belongs to the crypto
 *     layer, which has its own requirements.
 *   - No seeding API. There is no way for a caller to seed the
 *     generator. This is deliberate: a caller-supplied seed is
 *     the most common way to weaken a random generator.
 *   - No global state exposed. The generator's state is
 *     private. A caller that needs reproducible output must
 *     use a different module.
 *   - No I/O. Nothing here reads or writes a file, a socket,
 *     or a log.
 *   - No allocation. Every function writes to caller-supplied
 *     storage.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * Two generators are exposed:
 *
 *   - A fast generator, for non-security-sensitive uses such as
 *     jitter in retransmission, port selection, and DHT bucket
 *     shuffling. It is a small, deterministic, seedable
 *     generator. Its state is private; it cannot be seeded
 *     from outside this module.
 *
 *   - A secure generator, for nonces, session IDs, grant IDs,
 *     DHT tokens, and any other value where predictability
 *     would be a security problem. It reads from the platform
 *     entropy source.
 *
 * The two are not interchangeable. A caller that needs a
 * security property must use the secure generator. A caller
 * that needs speed and does not need a security property may
 * use the fast generator.
 *
 * The fast generator is a 64-bit variant of the SplitMix64
 * mixing function applied to a counter. It is not a
 * cryptographic generator. It passes the usual statistical
 * tests and is fast; it is not intended to resist an attacker
 * who can observe its output and wants to predict the next
 * value.
 *
 * The secure generator reads from the platform's entropy
 * source. On a POSIX platform this is getrandom(2) or
 * /dev/urandom. The exact source is an implementation detail
 * and may change. What does not change is the contract: a
 * caller that needs a value an attacker cannot predict uses
 * this generator.
 *
 * Both generators fill a caller-supplied buffer. The fast
 * generator also exposes single-value functions for u32 and
 * u64, because that is the common shape for jitter.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <stdint.h>                    uint32_t, uint64_t
 *   <stddef.h>                    size_t
 *   "bowie/err.h"                 bowie_error_t
 * ============================================================================
 */

#ifndef BOWIE_CORE_INTERNAL_RAND_H
#define BOWIE_CORE_INTERNAL_RAND_H

#include <stdint.h>
#include <stddef.h>

#include "bowie/err.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ============================================================================
 * FAST GENERATOR
 * ============================================================================
 *
 * A small, deterministic, non-cryptographic generator.
 *
 * It is seeded once, on first use, from the platform entropy
 * source. After that, it is a pure function of its internal
 * state. The state is private; there is no API to read or
 * write it.
 *
 * The generator is not thread-safe. Two threads that call it
 * concurrently may produce the same value. A caller that needs
 * a per-thread generator must provide one itself.
 */

/*
 * Return a non-zero 64-bit value from the fast generator.
 *
 * A zero result is possible with negligible probability. A
 * caller that needs to avoid zero must retry.
 */
uint64_t bowie_rand_fast_u64(void);

/*
 * Return a 32-bit value from the fast generator. The value
 * uses the top 32 bits of the next 64-bit output.
 */
uint32_t bowie_rand_fast_u32(void);

/*
 * Fill a caller-supplied buffer with bytes from the fast
 * generator.
 *
 * Passing NULL for buf is a no-op.
 */
void bowie_rand_fast_bytes(void *buf, size_t n);

/*
 * Return a 64-bit value in the range [0, bound).
 *
 * Passing a bound of 0 is a programming error; the function
 * returns 0.
 */
uint64_t bowie_rand_fast_below(uint64_t bound);

/*
 * ============================================================================
 * SECURE GENERATOR
 * ============================================================================
 *
 * A generator that reads from the platform entropy source.
 *
 * Every call reads fresh entropy. There is no cached state and
 * no deterministic sequence. Two calls with the same length
 * return independent values.
 *
 * This generator is the one to use for nonces, session IDs,
 * grant IDs, DHT tokens, and any other value where
 * predictability would be a security problem.
 */

/*
 * Fill a caller-supplied buffer with bytes from the platform
 * entropy source.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NULL_ARG if buf is NULL and n > 0.
 * Returns BOWIE_ERR_INVAL if n is 0 and the platform refuses
 *   a zero-length read.
 * Returns a NETWORK-class error if the platform entropy source
 *   cannot be read.
 *
 * Passing n == 0 is a no-op and returns BOWIE_OK.
 */
bowie_error_t bowie_rand_secure_bytes(void *buf, size_t n);

/*
 * Return a non-zero 64-bit value from the platform entropy
 * source.
 *
 * Returns BOWIE_OK on success and stores the value through
 * out.
 *
 * Returns BOWIE_ERR_NULL_ARG if out is NULL.
 * Returns a NETWORK-class error if the platform entropy source
 *   cannot be read.
 *
 * The value is guaranteed to be non-zero. A platform that
 * returns zero is retried; after a small number of retries the
 * function returns an error rather than a zero.
 */
bowie_error_t bowie_rand_secure_u64(uint64_t *out);

/*
 * Return a non-zero 32-bit value from the platform entropy
 * source.
 *
 * Same contract as bowie_rand_secure_u64, with a 32-bit result.
 */
bowie_error_t bowie_rand_secure_u32(uint32_t *out);

/*
 * Return a 64-bit value in the range [0, bound) from the
 * platform entropy source.
 *
 * The result is unbiased: the modulo bias is removed by
 * rejection sampling.
 *
 * Passing a bound of 0 is a programming error; the function
 * returns 0 with an ARGUMENT-class error.
 */
bowie_error_t bowie_rand_secure_below(uint64_t bound,
                                      uint64_t *out);

/*
 * ============================================================================
 * END OF INTERNAL RANDOM
 * ============================================================================
 */

#ifdef __cplusplus
}
#endif

#endif /* BOWIE_CORE_INTERNAL_RAND_H */
