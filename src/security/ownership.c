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
 * signature verification in security/sign.h. This file does
 * not implement the signature check itself; it validates the
 * arguments, calls the security layer, and maps the result.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No signature algorithm. Ed25519 is implemented by
 *     OpenSSL and wrapped by security/sign.c.
 *   - No challenge generation. The caller supplies the
 *     challenge.
 *   - No I/O.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * The public ID is the raw Ed25519 public key. The security
 * layer expects a bowie_sign_public_t struct; the conversion
 * between the raw bytes and that format is handled by
 * security/sign.h, not here.
 *
 * A zero-length challenge is rejected before the security
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
 *   <string.h>              memcpy
 *   "bowie/types.h"         bowie_span_t, bowie_public_id_t
 *   "bowie/err.h"           bowie_error_t and codes
 *   "security/sign.h"       bowie_security_verify()
 *   "security/ownership.h"  declarations
 * ============================================================================
 */

#include <string.h>

#include "bowie/types.h"
#include "bowie/err.h"
#include "security/sign.h"        /* ← ប្តូរមកប្រើ security/sign.h */
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
    bowie_sign_public_t    pub_key;
    bowie_sign_signature_t sig;
    bowie_error_t          rc;

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

    if (signature.len != BOWIE_SIGN_SIGNATURE_LEN) {
        return BOWIE_ERR_SIGN_INVALID;
    }

    /*
     * Convert the raw public ID bytes into the security
     * layer's public key struct.
     */
    memcpy(pub_key.bytes, public_id->bytes, BOWIE_SIGN_PUBLIC_LEN);
    memcpy(sig.bytes, signature.data, BOWIE_SIGN_SIGNATURE_LEN);

    /*
     * The signature verification is delegated to the security
     * layer.
     */
    rc = bowie_security_verify(&pub_key,
                                challenge.data,
                                challenge.len,
                                &sig);

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
