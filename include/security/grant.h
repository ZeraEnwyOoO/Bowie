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
 * BOWIE — SECURITY: GRANT
 * ============================================================================
 *
 * Permission grant definition and operations.
 *
 * A grant is a cryptographic authorization issued by an Owner
 * (the peer sharing Internet) to a Subject (the peer receiving
 * Internet). It states what the subject is allowed to do and
 * for how long, and it is signed by the owner's private key.
 *
 * The grant is the core of the PoO (Proof of Ownership) model.
 * There is no central server that stores grants; the owner
 * holds the private key, the public key is the owner's
 * identity, and the signed grant is the proof that a subject
 * is allowed to connect.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No key generation. The owner's keypair is created by the
 *     crypto/keypair module.
 *   - No session management. Verifying a grant is not the same
 *     as establishing a session; the session layer handles the
 *     challenge-response that proves the subject holds the key.
 *   - No revocation list. Revocation is a separate concern
 *     handled by the revoke module.
 *   - No network I/O. This header declares pure value
 *     operations on a grant struct.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * The grant is a fixed-size value type. It can be copied,
 * stored, and compared without allocation.
 *
 * The signature covers the canonical serialization of the
 * grant fields. A verifier serializes the fields in the same
 * order and verifies the signature against the issuer's public
 * key. The serialization format is defined by the protocol
 * layer, not by this header.
 *
 * The subject field is the peer ID of the receiving peer. The
 * issuer field is the public ID of the owner. Both are fixed
 * byte arrays; the header does not derive one from the other.
 *
 * The grant_id is a nonce chosen by the owner. It is used to
 * identify the grant for revocation and for logging. Two
 * grants with the same fields but different IDs are distinct.
 *
 * The issued_at and expires_at fields are wall-clock times in
 * milliseconds. The grant is valid only when the current time
 * is between them, inclusive of issued_at and exclusive of
 * expires_at.
 *
 * The permissions field is a bitmask. The bits that are
 * meaningful are defined by the capabilities module; this
 * header treats the field as an opaque 32-bit value.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <stdint.h>              uint32_t, uint64_t
 *   "bowie/types.h"         bowie_peer_id_t, bowie_public_id_t,
 *                           bowie_grant_id_t, bowie_wtime_t,
 *                           bowie_grant_t
 *   "bowie/err.h"           bowie_error_t
 * ============================================================================
 */

#ifndef BOWIE_SECURITY_GRANT_H
#define BOWIE_SECURITY_GRANT_H

#include <stdint.h>

#include "bowie/types.h"
#include "bowie/err.h"
#include "security/sign.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ============================================================================
 * GRANT STRUCT
 * ============================================================================
 *
 * The grant is opaque in bowie/types.h (a forward declaration).
 * The full definition lives here because the security layer is
 * the only layer that needs to see its layout.
 *
 * A caller that only passes a grant around uses the handle.
 * A caller that reads or writes the fields includes this
 * header.
 */

struct bowie_grant {
    bowie_peer_id_t   subject;     /* who receives the permission */
    bowie_public_id_t issuer;      /* who grants the permission */
    bowie_grant_id_t  grant_id;    /* nonce chosen by the issuer */
    uint32_t          permissions; /* bitmask of allowed actions */
    bowie_wtime_t     issued_at;   /* wall-clock, milliseconds */
    bowie_wtime_t     expires_at;  /* wall-clock, milliseconds */
    uint64_t          max_egress_bytes; /* zero means unlimited */
    uint8_t           signature[64]; /* Ed25519 signature */
};

#define BOWIE_GRANT_WIRE_LEN (BOWIE_PEER_ID_LEN + BOWIE_PUBLIC_ID_LEN + \
                              BOWIE_GRANT_ID_LEN + 4u + 8u + 8u + 8u + 64u)

/* Permissions carried by owner-issued internet access grants. */
#define BOWIE_GRANT_INTERNET_USE   (1u << 0)
#define BOWIE_GRANT_INTERNET_RELAY (1u << 1)

/*
 * ============================================================================
 * LIFECYCLE
 * ============================================================================
 */

/*
 * Reset a grant to the unset state.
 *
 * Every field becomes zero. A grant in this state has no
 * subject, no issuer, no permissions, and no signature.
 *
 * Passing NULL is a no-op.
 */
void bowie_grant_clear(bowie_grant_t *grant);

/*
 * ============================================================================
 * SERIALIZATION
 * ============================================================================
 *
 * The grant is serialized for signing and verification. The
 * serialization is deterministic: the same grant always
 * produces the same bytes. The format is defined by the
 * protocol layer, not by this header.
 */

/*
 * Serialize the grant fields (without the signature) into a
 * caller-supplied buffer.
 *
 * The serialization covers the fields in the order they appear
 * in the struct: subject, issuer, grant_id, permissions,
 * issued_at, expires_at, max_egress_bytes.
 *
 * Returns the number of bytes written.
 * Returns BOWIE_ERR_NULL_ARG if grant or buf is NULL.
 * Returns BOWIE_ERR_TOO_SMALL if cap is smaller than the
 * serialized form.
 */
long bowie_grant_serialize(const bowie_grant_t *grant,
                           uint8_t *buf,
                           size_t cap);

/* Decode the canonical fields followed by the 64-byte Ed25519 signature. */
bowie_error_t bowie_grant_deserialize(const uint8_t *wire, size_t wire_len,
                                      bowie_grant_t *out);

/* Sign or verify the canonical grant fields with the issuer's key. */
bowie_error_t bowie_grant_sign(bowie_grant_t *grant,
                               const bowie_sign_private_t *private_key);
bowie_error_t bowie_grant_verify(const bowie_grant_t *grant);

/*
 * Return the exact size of the serialized grant fields, in
 * bytes. The signature is not included.
 *
 * Passing NULL returns 0.
 */
size_t bowie_grant_serialized_len(const bowie_grant_t *grant);

/*
 * ============================================================================
 * VALIDATION
 * ============================================================================
 *
 * Helpers that a verifier uses after the signature has been
 * checked. They do not verify the signature themselves; that
 * is done by the crypto/sign module.
 */

/*
 * True when the grant is time-valid at the given wall-clock
 * time.
 *
 * A grant is time-valid when:
 *
 *   - it has a non-zero issued_at,
 *   - it has a non-zero expires_at,
 *   - now is greater than or equal to issued_at,
 *   - now is strictly less than expires_at.
 *
 * A grant with issued_at >= expires_at is never time-valid.
 */
int bowie_grant_is_time_valid(const bowie_grant_t *grant,
                              bowie_wtime_t now);

/*
 * True when the grant names the given subject.
 *
 * The comparison is on the subject peer ID. A grant with an
 * unset subject does not match any peer.
 */
int bowie_grant_matches_subject(const bowie_grant_t *grant,
                                const bowie_peer_id_t *subject);

/*
 * True when the grant names the given issuer.
 *
 * The comparison is on the issuer public ID. A grant with an
 * unset issuer does not match any owner.
 */
int bowie_grant_matches_issuer(const bowie_grant_t *grant,
                               const bowie_public_id_t *issuer);

/*
 * True when the grant allows the given capability bit.
 *
 * The permissions field is treated as a 32-bit mask. A grant
 * with zero permissions allows nothing.
 */
int bowie_grant_allows(const bowie_grant_t *grant,
                       uint32_t capability_bit);

/*
 * ============================================================================
 * END OF SECURITY GRANT
 * ============================================================================
 */

#ifdef __cplusplus
}
#endif

#endif /* BOWIE_SECURITY_GRANT_H */
