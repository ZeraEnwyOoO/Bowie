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
 * BOWIE — SECURITY: KEYPAIR
 * ============================================================================
 *
 * X25519 key agreement for the security layer.
 *
 * This header declares the X25519 key agreement functions the
 * security layer uses. It is independent of crypto/keypair.h.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No Ed25519. Signing is in security/sign.h.
 *   - No encryption. Symmetric encryption is in security/session.h.
 *   - No key storage.
 *   - No allocation.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * X25519 keys are 32 bytes. A public key is 32 bytes; a
 * private key is 32 bytes; the shared secret is 32 bytes.
 *
 * The shared secret is not a symmetric key. It must be passed
 * through a KDF (HKDF-SHA256, as in security/session.c).
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <stdint.h>              uint8_t
 *   <stddef.h>              size_t
 *   "bowie/types.h"         bowie_keypair_public_t,
 *                           bowie_keypair_private_t,
 *                           bowie_keypair_shared_t
 *   "bowie/err.h"           bowie_error_t
 * ============================================================================
 */

#ifndef BOWIE_SECURITY_KEYPAIR_H
#define BOWIE_SECURITY_KEYPAIR_H

#include <stdint.h>
#include <stddef.h>

#include "bowie/types.h"
#include "bowie/err.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ============================================================================
 * GENERATION
 * ============================================================================
 */

/*
 * Generate an X25519 keypair.
 *
 * On success, both keys are written through the out pointers.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NULL_ARG if either out pointer is NULL.
 * Returns BOWIE_ERR_CRYPTO if the underlying library or the
 *   entropy source reports a failure.
 */
bowie_error_t bowie_security_keypair_generate(
    bowie_keypair_public_t *out_public,
    bowie_keypair_private_t *out_private);

/*
 * ============================================================================
 * AGREEMENT
 * ============================================================================
 */

/*
 * Compute the shared secret between a local private key and a
 * remote public key.
 *
 * The shared secret is 32 bytes. It is not a symmetric key;
 * a caller that needs one must pass the secret through a KDF.
 *
 * Returns BOWIE_OK on success.
 * Returns BOWIE_ERR_NULL_ARG if any pointer is NULL.
 * Returns BOWIE_ERR_CRYPTO if the underlying library reports a
 *   failure.
 */
bowie_error_t bowie_security_keypair_shared(
    const bowie_keypair_private_t *local_private,
    const bowie_keypair_public_t *remote_public,
    bowie_keypair_shared_t *out);

/*
 * ============================================================================
 * END OF SECURITY KEYPAIR
 * ============================================================================
 */

#ifdef __cplusplus
}
#endif

#endif /* BOWIE_SECURITY_KEYPAIR_H */
