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
 * BOWIE — SECURITY: OWNERSHIP (IMPLEMENTATION)
 * ============================================================================
 *
 * Implementation of the Proof of Ownership helpers declared in
 * security/ownership.h.
 *
 * The verification is a thin wrapper around the Ed25519
 * signature verification in crypto/sign.h. This file does not
 * implement the signature check itself; it validates the
 * arguments, calls the crypto layer, and maps the result.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No signature algorithm. Ed25519 is implemented by
 *     OpenSSL and wrapped by crypto/sign.c.
 *   - No challenge generation. The caller supplies the
 *     challenge.
 *   - No I/O.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * The public ID is the raw Ed25519 public key. The crypto
 * layer expects a key in a specific format; the conversion
 * between the raw bytes and that format is handled by
 * crypto/sign.h, not here.
 *
 * A zero-length challenge is rejected before the crypto
 * layer is called. A zero-length challenge would produce a
 * signature over nothing, which is meaningless as a proof.
 *
 * A zero-length signature is rejected for the same reason: a
 * signature of nothing cannot be a valid Ed25519 signature.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   "bowie/types.h"         bowie_span_t, bowie_public_id_t
 *   "bowie/err.h"           bowie_error_t and codes
 *   "crypto/sign.h"         bowie_sign_verify()
 *   "security/ownership.h"  declarations
 * ============================================================================
 */

#include "bowie/types.h"
#include "bowie/err.h"
#include "crypto/sign.h"
#include "security/ownership.h"

/*
 * ============================================================================
 * VERIFY
 * ============================================================================
 */

bowie_error_t bowie_ownership_verify(const bowie_public_id_t *public_id,
                                     bowie_span_t challenge,
                                     bowie_span_t signature)
{
    int rc;

    if (public_id == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }

    if (challenge.data == NULL && challenge.len > 0) {
        return BOWIE_ERR_NULL_ARG;
    }

    if (signature.data == NULL && signature.len > 0) {
        return BOWIE_ERR_NULL_ARG;
    }

    if (challenge.len == 0) {
        return BOWIE_ERR_TOO_SMALL;
    }

    if (signature.len == 0) {
        return BOWIE_ERR_TOO_SMALL;
    }

    /*
     * The signature verification is delegated to the crypto
     * layer. The public ID is passed as raw bytes; the crypto
     * layer converts it to its internal key format.
     */
    rc = bowie_sign_verify(public_id->bytes,
                           BOWIE_PUBLIC_ID_LEN,
                           challenge.data,
                           challenge.len,
                           signature.data,
                           signature.len);

    if (rc != BOWIE_OK) {
        return BOWIE_ERR_SIGN_INVALID;
    }

    return BOWIE_OK;
}

/*
 * ============================================================================
 * HELPERS
 * ============================================================================
 */

int bowie_ownership_is_valid(const bowie_public_id_t *public_id,
                             bowie_span_t challenge,
                             bowie_span_t signature)
{
    bowie_error_t rc;

    rc = bowie_ownership_verify(public_id, challenge, signature);

    return (rc == BOWIE_OK) ? 1 : 0;
}

/*
 * ============================================================================
 * END OF SECURITY OWNERSHIP IMPLEMENTATION
 * ============================================================================
 */
