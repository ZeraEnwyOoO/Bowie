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
 * BOWIE — SECURITY: SIGN
 * ============================================================================
 *
 * Ed25519 signatures for the security layer.
 *
 * This header declares the signing functions and types the
 * security layer uses. It is independent of crypto/sign.h.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No key generation. The caller generates the keypair.
 *   - No encryption. Symmetric encryption is in security/session.h.
 *   - No certificate parsing.
 *   - No streaming API.
 *   - No allocation.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * The private key is 64 bytes (seed || public) in the form
 * OpenSSL expects. The first 32 bytes are the seed, the second
 * 32 bytes are the public key.
 *
 * The signature is 64 bytes.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <stdint.h>              uint8_t
 *   <stddef.h>              size_t
 *   "bowie/types.h"         (no sign types are declared there)
 *   "bowie/err.h"           bowie_error_t
 * ============================================================================
 */

#ifndef BOWIE_SECURITY_SIGN_H
#define BOWIE_SECURITY_SIGN_H

#include <stdint.h>
#include <stddef.h>

#include "bowie/types.h"
#include "bowie/err.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ============================================================================
 * TYPES
 * ============================================================================
 *
 * Fixed-size value types. A key or a signature can be copied
 * and compared without allocation.
 */

#define BOWIE_SIGN_PUBLIC_LEN    32
#define BOWIE_SIGN_PRIVATE_LEN   64
#define BOWIE_SIGN_SIGNATURE_LEN 64

typedef struct bowie_sign_public {
    uint8_t bytes[BOWIE_SIGN_PUBLIC_LEN];
} bowie_sign_public_t;

typedef struct bowie_sign_private {
    uint8_t bytes[BOWIE_SIGN_PRIVATE_LEN];
} bowie_sign_private_t;

typedef struct bowie_sign_signature {
    uint8_t bytes[BOWIE_SIGN_SIGNATURE_LEN];
} bowie_sign_signature_t;

/*
 * ============================================================================
 * SIGN
 * ============================================================================
 */

bowie_error_t bowie_security_sign(
    const bowie_sign_private_t *private_key,
    const void *msg, size_t msg_len,
    bowie_sign_signature_t *out);

bowie_error_t bowie_security_verify(
    const bowie_sign_public_t *public_key,
    const void *msg, size_t msg_len,
    const bowie_sign_signature_t *signature);

/*
 * ============================================================================
 * END OF SECURITY SIGN
 * ============================================================================
 */

#ifdef __cplusplus
}
#endif

#endif /* BOWIE_SECURITY_SIGN_H */
