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
 * BOWIE — SECURITY: GRANT (IMPLEMENTATION)
 * ============================================================================
 *
 * Implementation of the grant helpers declared in
 * security/grant.h.
 *
 * The helpers are pure value operations. They do not touch
 * the network, do not allocate, and do not verify the
 * signature (that is the crypto/sign module's job).
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No signature verification.
 *   - No I/O.
 *   - No allocation.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * Serialization is byte-oriented and big-endian. The cursor
 * helpers from core/internal/bytes.h do the writing; the
 * format is the order the fields appear in the struct.
 *
 * The signature is not part of the serialized form. A signer
 * serializes the fields, signs the bytes, and stores the
 * signature in the struct. A verifier serializes the fields
 * the same way, and verifies the signature against the
 * issuer's public key.
 *
 * Time validity is checked with a single comparison. A grant
 * whose issued_at is not before expires_at is never valid.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <string.h>                memset
 *   "bowie/types.h"           types
 *   "bowie/err.h"             errors
 *   "core/internal/bytes.h"   cursor helpers
 *   "security/grant.h"        declarations
 * ============================================================================
 */

#include <string.h>

#include "bowie/types.h"
#include "bowie/err.h"
#include "core/internal/bytes.h"
#include "security/grant.h"

/*
 * ============================================================================
 * LIFECYCLE
 * ============================================================================
 */

void bowie_grant_clear(bowie_grant_t *grant)
{
    if (grant == NULL) {
        return;
    }

    memset(grant, 0, sizeof(*grant));
}

/*
 * ============================================================================
 * SERIALIZATION
 * ============================================================================
 */

size_t bowie_grant_serialized_len(const bowie_grant_t *grant)
{
    if (grant == NULL) {
        return 0;
    }

    return BOWIE_PEER_ID_LEN
         + BOWIE_PUBLIC_ID_LEN
         + BOWIE_GRANT_ID_LEN
         + 4
         + 8
         + 8
         + 8;
}

long bowie_grant_serialize(const bowie_grant_t *grant,
                           uint8_t *buf,
                           size_t cap)
{
    bowie_cursor_t c;

    if (grant == NULL || buf == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }

    if (cap < bowie_grant_serialized_len(grant)) {
        return BOWIE_ERR_TOO_SMALL;
    }

    bowie_cursor_init(&c, buf, cap);

    /* Subject */
    if (bowie_cursor_put_raw(&c, grant->subject.bytes,
                             BOWIE_PEER_ID_LEN) == 0) {
        return BOWIE_ERR_TOO_SMALL;
    }

    /* Issuer */
    if (bowie_cursor_put_raw(&c, grant->issuer.bytes,
                             BOWIE_PUBLIC_ID_LEN) == 0) {
        return BOWIE_ERR_TOO_SMALL;
    }

    /* Grant ID */
    if (bowie_cursor_put_raw(&c, grant->grant_id.bytes,
                             BOWIE_GRANT_ID_LEN) == 0) {
        return BOWIE_ERR_TOO_SMALL;
    }

    /* Permissions */
    if (bowie_cursor_put_be32(&c, grant->permissions) == 0) {
        return BOWIE_ERR_TOO_SMALL;
    }

    /* Issued at */
    if (bowie_cursor_put_be64(&c, grant->issued_at) == 0) {
        return BOWIE_ERR_TOO_SMALL;
    }

    /* Expires at */
    if (bowie_cursor_put_be64(&c, grant->expires_at) == 0) {
        return BOWIE_ERR_TOO_SMALL;
    }

    /* Cumulative source-egress byte cap; zero represents unlimited. */
    if (bowie_cursor_put_be64(&c, grant->max_egress_bytes) == 0) {
        return BOWIE_ERR_TOO_SMALL;
    }

    return (long)c.pos;
}

bowie_error_t bowie_grant_deserialize(const uint8_t *wire, size_t wire_len,
                                      bowie_grant_t *out)
{
    bowie_cursor_t c;
    bowie_error_t rc;
    if (wire == NULL || out == NULL) return BOWIE_ERR_NULL_ARG;
    if (wire_len != BOWIE_GRANT_WIRE_LEN) return BOWIE_ERR_FORMAT;
    bowie_grant_clear(out);
    bowie_cursor_init(&c, (void *)wire, wire_len);
    rc = bowie_cursor_get_raw(&c, out->subject.bytes, BOWIE_PEER_ID_LEN);
    if (rc != BOWIE_OK) return rc;
    rc = bowie_cursor_get_raw(&c, out->issuer.bytes, BOWIE_PUBLIC_ID_LEN);
    if (rc != BOWIE_OK) return rc;
    rc = bowie_cursor_get_raw(&c, out->grant_id.bytes, BOWIE_GRANT_ID_LEN);
    if (rc != BOWIE_OK) return rc;
    rc = bowie_cursor_get_be32(&c, &out->permissions);
    if (rc != BOWIE_OK) return rc;
    rc = bowie_cursor_get_be64(&c, &out->issued_at);
    if (rc != BOWIE_OK) return rc;
    rc = bowie_cursor_get_be64(&c, &out->expires_at);
    if (rc != BOWIE_OK) return rc;
    rc = bowie_cursor_get_be64(&c, &out->max_egress_bytes);
    if (rc != BOWIE_OK) return rc;
    return bowie_cursor_get_raw(&c, out->signature, sizeof(out->signature));
}

bowie_error_t bowie_grant_sign(bowie_grant_t *grant,
                               const bowie_sign_private_t *private_key)
{
    static const uint8_t domain[] = "Bowie owner grant v2";
    uint8_t serialized[sizeof(domain) + BOWIE_GRANT_WIRE_LEN - 64u];
    bowie_sign_signature_t signature;
    long len;
    bowie_error_t rc;
    if (grant == NULL || private_key == NULL) return BOWIE_ERR_NULL_ARG;
    memcpy(serialized, domain, sizeof(domain));
    len = bowie_grant_serialize(grant, serialized + sizeof(domain),
                                sizeof(serialized) - sizeof(domain));
    if (len < 0) return (bowie_error_t)len;
    rc = bowie_security_sign(private_key, serialized,
                             sizeof(domain) + (size_t)len, &signature);
    if (rc == BOWIE_OK) memcpy(grant->signature, signature.bytes,
                               sizeof(grant->signature));
    return rc;
}

bowie_error_t bowie_grant_verify(const bowie_grant_t *grant)
{
    static const uint8_t domain[] = "Bowie owner grant v2";
    uint8_t serialized[sizeof(domain) + BOWIE_GRANT_WIRE_LEN - 64u];
    bowie_sign_public_t public_key;
    bowie_sign_signature_t signature;
    long len;
    if (grant == NULL) return BOWIE_ERR_NULL_ARG;
    memcpy(serialized, domain, sizeof(domain));
    len = bowie_grant_serialize(grant, serialized + sizeof(domain),
                                sizeof(serialized) - sizeof(domain));
    if (len < 0) return (bowie_error_t)len;
    memcpy(public_key.bytes, grant->issuer.bytes, sizeof(public_key.bytes));
    memcpy(signature.bytes, grant->signature, sizeof(signature.bytes));
    return bowie_security_verify(&public_key, serialized,
                                 sizeof(domain) + (size_t)len,
                                 &signature) == BOWIE_OK
        ? BOWIE_OK : BOWIE_ERR_SIGN_INVALID;
}

/*
 * ============================================================================
 * VALIDATION
 * ============================================================================
 */

int bowie_grant_is_time_valid(const bowie_grant_t *grant,
                              bowie_wtime_t now)
{
    if (grant == NULL) {
        return 0;
    }

    if (grant->issued_at == 0 || grant->expires_at == 0) {
        return 0;
    }

    if (grant->issued_at >= grant->expires_at) {
        return 0;
    }

    if (now < grant->issued_at) {
        return 0;
    }

    if (now >= grant->expires_at) {
        return 0;
    }

    return 1;
}

int bowie_grant_matches_subject(const bowie_grant_t *grant,
                                const bowie_peer_id_t *subject)
{
    if (grant == NULL || subject == NULL) {
        return 0;
    }

    if (bowie_peer_id_is_zero(&grant->subject)) {
        return 0;
    }

    return bowie_peer_id_equal(&grant->subject, subject);
}

int bowie_grant_matches_issuer(const bowie_grant_t *grant,
                               const bowie_public_id_t *issuer)
{
    if (grant == NULL || issuer == NULL) {
        return 0;
    }

    if (bowie_public_id_is_zero(&grant->issuer)) {
        return 0;
    }

    return bowie_public_id_equal(&grant->issuer, issuer);
}

int bowie_grant_allows(const bowie_grant_t *grant,
                       uint32_t capability_bit)
{
    if (grant == NULL) {
        return 0;
    }

    if (grant->permissions == 0) {
        return 0;
    }

    return (grant->permissions & capability_bit) != 0 ? 1 : 0;
}

/*
 * ============================================================================
 * END OF SECURITY GRANT IMPLEMENTATION
 * ============================================================================
 */
