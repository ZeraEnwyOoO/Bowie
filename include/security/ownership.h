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
 * BOWIE — SECURITY: OWNERSHIP (PoO)
 * ============================================================================
 *
 * Proof of Ownership (PoO) verification.
 *
 * PoO is the mechanism by which a peer proves it holds the
 * private key corresponding to a public ID. It is used in
 * three places:
 *
 *   - Setup: the owner establishes their identity.
 *   - Grant: the owner signs a permission for a subject.
 *   - Session: a peer proves it is allowed to use a grant.
 *
 * The proof is a signature over a challenge. The verifier
 * generates the challenge, the prover signs it with its
 * private key, and the verifier checks the signature against
 * the claimed public key.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No key generation. The keypair is created by the
 *     crypto/keypair module.
 *   - No challenge generation. The verifier generates the
 *     challenge; this header only verifies the response.
 *   - No session management. Session establishment is a
 *     separate concern handled by the session module.
 *   - No network I/O. The challenge and response are
 *     byte buffers supplied by the caller.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * The challenge is an opaque byte buffer. The verifier
 * chooses its size and content; the prover signs it as-is.
 * A typical challenge is 32 random bytes, which makes a
 * replay attack impractical without additional measures.
 *
 * The response is the signature over the challenge. The
 * signature must be exactly BOWIE_SIGN_SIGNATURE_LEN (64)
 * bytes, which is the Ed25519 signature size. A signature of
 * any other size is rejected before the crypto layer is
 * called.
 *
 * The public key is supplied by the verifier, not by the
 * prover: the verifier must already know the key it is
 * checking against, or the check is meaningless.
 *
 * The signature algorithm is Ed25519. The verifier does not
 * know which algorithm the prover used; the signature
 * verifies or it does not.
 *
 * The verification functions are pure: they do not allocate,
 * do not touch the network, and do not depend on global
 * state.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <stdint.h>              uint8_t
 *   <stddef.h>              size_t
 *   "bowie/types.h"         bowie_span_t, bowie_public_id_t
 *   "bowie/err.h"           bowie_error_t
 * ============================================================================
 */

#ifndef BOWIE_SECURITY_OWNERSHIP_H
#define BOWIE_SECURITY_OWNERSHIP_H

#include <stdint.h>
#include <stddef.h>

#include "bowie/types.h"
#include "bowie/err.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ============================================================================
 * VERIFY
 * ============================================================================
 */

/*
 * Verify a Proof of Ownership.
 *
 * The proof is a signature over the challenge, produced by
 * the prover's private key. The verifier checks the signature
 * against the prover's claimed public key.
 *
 * The public key is supplied by the verifier, not by the
 * prover. The verifier must already trust the binding between
 * the public key and the peer identity before calling this
 * function.
 *
 * The signature must be exactly 64 bytes (Ed25519). The
 * challenge may be any non-zero length.
 *
 * Returns BOWIE_OK when the signature is valid.
 * Returns BOWIE_ERR_NULL_ARG if any pointer is NULL.
 * Returns BOWIE_ERR_TOO_SMALL if the challenge length is zero.
 * Returns BOWIE_ERR_SIGN_INVALID if the signature does not
 *   verify or has the wrong length.
 */
bowie_error_t bowie_ownership_verify(const bowie_public_id_t *public_id,
                                     bowie_span_t challenge,
                                     bowie_span_t signature);

/*
 * ============================================================================
 * HELPERS
 * ============================================================================
 */

/*
 * True when the proof of ownership is valid.
 *
 * This is the boolean form of bowie_ownership_verify(). A
 * caller that wants the error code calls the verify function
 * directly.
 */
int bowie_ownership_is_valid(const bowie_public_id_t *public_id,
                             bowie_span_t challenge,
                             bowie_span_t signature);

/*
 * ============================================================================
 * END OF SECURITY OWNERSHIP
 * ============================================================================
 */

#ifdef __cplusplus
}
#endif

#endif /* BOWIE_SECURITY_OWNERSHIP_H */
