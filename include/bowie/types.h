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
 * BOWIE — BASIC TYPES
 * ============================================================================
 *
 * Foundational data types shared across the Bowie library.
 *
 * This header is the lowest layer of the public contract. It
 * declares types only; it does not declare functions. Functions
 * that operate on these types are declared in the headers that
 * own the relevant capability.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No allocation. Types are value types with fixed or
 *     caller-managed storage.
 *   - No I/O. No function here touches a socket, a file, or the
 *     network.
 *   - No error handling beyond the error type re-export. This
 *     header includes err.h so that a caller can use one include
 *     for the two foundational contracts, but it does not add
 *     error behavior.
 *   - No platform-specific layout. All types are declared in
 *     terms of fixed-width integers and byte arrays, so the same
 *     header works on every platform Bowie targets.
 *   - No opaque handles. Handles that hide implementation
 *     (engine, session, gateway) are declared by the header that
 *     owns the capability, not here.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * Types in this file fall into three groups:
 *
 *   1. Byte and buffer types. Fixed-capacity, no allocation.
 *      These are the building blocks for every other type.
 *
 *   2. Address types. A family tag plus a fixed-size address
 *      payload. No sockaddr, no sockaddr_storage; those are a
 *      platform concern and are converted at the boundary.
 *
 *   3. Identity types. Peer ID and public ID. Both are fixed
 *      byte arrays with a documented derivation. Neither is a
 *      pointer, so identity can be copied and compared without
 *      allocation.
 *
 * Sizes are chosen to match the underlying cryptographic
 * primitives:
 *
 *   - Peer ID is 160 bits (20 bytes), derived from the Ed25519
 *     public key by the hash function in use. 160 bits matches
 *     the DHT identifier space.
 *
 *   - Public ID is the full Ed25519 public key, 32 bytes.
 *
 *   - Session IDs and grant IDs are 128 bits (16 bytes) to make
 *     accidental collision negligible for the lifetime of a
 *     session or a grant.
 *
 * Address payloads are large enough to hold IPv6 (16 bytes) so
 * that one type covers both families. The family tag selects
 * the meaningful prefix.
 *
 * All byte arrays are declared as uint8_t and are expected to
 * hold binary data, not text. Text representations are produced
 * by conversion functions in the owning headers, not stored
 * here.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <stdint.h>      fixed-width integers
 *   <stddef.h>      size_t
 *   "bowie/err.h"   error type re-export
 * ============================================================================
 */

#ifndef BOWIE_TYPES_H
#define BOWIE_TYPES_H

#include <stdint.h>
#include <stddef.h>

#include "bowie/err.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ============================================================================
 * BYTE AND BUFFER TYPES
 * ============================================================================
 */

/*
 * A single byte. Named for readability in signatures that would
 * otherwise use unsigned char.
 */
typedef uint8_t bowie_byte_t;

/*
 * A borrowed, read-only byte span.
 *
 * The data pointer is not owned. The caller must keep the
 * underlying storage valid for the lifetime of the span.
 *
 * A span with len == 0 may have data == NULL or data != NULL;
 * both are valid. A span with len > 0 must have data != NULL.
 */
typedef struct bowie_span {
    const uint8_t *data;
    size_t         len;
} bowie_span_t;

/*
 * A mutable byte span.
 *
 * Same ownership rules as bowie_span_t, but the caller may
 * write through data.
 */
typedef struct bowie_mut_span {
    uint8_t *data;
    size_t   len;
} bowie_mut_span_t;

/*
 * A borrowed, read-only string slice.
 *
 * The data pointer is not owned and is not necessarily
 * NUL-terminated. The caller must keep the underlying storage
 * valid for the lifetime of the slice.
 *
 * A slice with len == 0 may have data == NULL or data != NULL.
 * A slice with len > 0 must have data != NULL.
 */
typedef struct bowie_str {
    const char *data;
    size_t      len;
} bowie_str_t;

/*
 * Fixed-capacity byte buffer.
 *
 * The capacity is a compile-time constant. The used length is
 * tracked separately. No allocation is performed by this type;
 * callers that need growable buffers must provide their own.
 */
#define BOWIE_BUF_CAP 512

typedef struct bowie_buf {
    uint8_t data[BOWIE_BUF_CAP];
    size_t  len;
} bowie_buf_t;

/*
 * ============================================================================
 * ADDRESS TYPES
 * ============================================================================
 */

/*
 * Address family tag.
 *
 * BOWIE_AF_UNSPEC means the address is unset. BOWIE_AF_INET and
 * BOWIE_AF_INET6 are the only supported families in v1.
 */
typedef enum bowie_af {
    BOWIE_AF_UNSPEC = 0,
    BOWIE_AF_INET   = 1,
    BOWIE_AF_INET6  = 2,
} bowie_af_t;

/*
 * A network address.
 *
 * The family tag selects the meaningful prefix of addr:
 *
 *   BOWIE_AF_INET  — the first 4 bytes hold the IPv4 address.
 *   BOWIE_AF_INET6 — all 16 bytes hold the IPv6 address.
 *   BOWIE_AF_UNSPEC — addr is ignored; the address is unset.
 *
 * The port is in host byte order. Serialization is the
 * responsibility of the protocol layer.
 */
typedef struct bowie_addr {
    bowie_af_t family;
    uint8_t    addr[16];
    uint16_t   port;
} bowie_addr_t;

/*
 * A network endpoint: an address paired with a transport
 * protocol tag.
 *
 * The transport tag is a plain integer so that this header does
 * not depend on a transport enum that belongs to the network
 * layer. The network layer defines the meaningful values.
 */
typedef struct bowie_endpoint {
    bowie_addr_t addr;
    uint8_t      transport;
} bowie_endpoint_t;

/*
 * ============================================================================
 * IDENTITY TYPES
 * ============================================================================
 */

/*
 * Peer ID.
 *
 * 160 bits, derived from the peer's Ed25519 public key by the
 * hash function in use. Used for DHT routing and for identity
 * within the peer layer.
 *
 * A peer ID with all bytes zero is reserved and means "unset".
 * Functions that return a peer ID must not produce an all-zero
 * value as a valid result.
 */
#define BOWIE_PEER_ID_LEN 20

typedef struct bowie_peer_id {
    uint8_t bytes[BOWIE_PEER_ID_LEN];
} bowie_peer_id_t;

/*
 * Public ID.
 *
 * The full Ed25519 public key. 32 bytes. Used as the owner's
 * public identity and as the subject of a permission grant.
 *
 * A public ID with all bytes zero is reserved and means "unset".
 */
#define BOWIE_PUBLIC_ID_LEN 32

typedef struct bowie_public_id {
    uint8_t bytes[BOWIE_PUBLIC_ID_LEN];
} bowie_public_id_t;

/*
 * Session ID.
 *
 * 128 bits, chosen by the session layer. Used to identify a
 * live session between a peer and a gateway. Not derived from
 * any key material; it is a nonce.
 *
 * An all-zero session ID is reserved and means "unset".
 */
#define BOWIE_SESSION_ID_LEN 16

typedef struct bowie_session_id {
    uint8_t bytes[BOWIE_SESSION_ID_LEN];
} bowie_session_id_t;

/*
 * Grant ID.
 *
 * 128 bits, chosen by the owner when a grant is created. Used
 * to identify a grant for revocation and for logging.
 *
 * An all-zero grant ID is reserved and means "unset".
 */
#define BOWIE_GRANT_ID_LEN 16

typedef struct bowie_grant_id {
    uint8_t bytes[BOWIE_GRANT_ID_LEN];
} bowie_grant_id_t;

/*
 * ============================================================================
 * TIME TYPES
 * ============================================================================
 */

/*
 * Monotonic time in milliseconds.
 *
 * Used for elapsed-time measurement. Not comparable across
 * processes or across reboots.
 */
typedef uint64_t bowie_mtime_t;

/*
 * Wall-clock time in milliseconds since the Unix epoch.
 *
 * Used for grant issue and expiry timestamps. May move backwards
 * if the system clock is adjusted; callers that need a strict
 * ordering must use bowie_mtime_t instead.
 */
typedef uint64_t bowie_wtime_t;

/*
 * ============================================================================
 * OPAQUE HANDLE FORWARD DECLARATIONS
 * ============================================================================
 *
 * Handles whose layout is private to their owning layer. The
 * forward declarations live here so that public signatures can
 * name them without including the owning header.
 *
 * Definitions live in the owning header, not here. Code that
 * needs to dereference a handle must include the owning header.
 */

typedef struct bowie_engine bowie_engine_t;
typedef struct bowie_session bowie_session_t;
typedef struct bowie_gateway bowie_gateway_t;
typedef struct bowie_dht bowie_dht_t;
typedef struct bowie_tunnel bowie_tunnel_t;
typedef struct bowie_nat bowie_nat_t;
typedef struct bowie_grant bowie_grant_t;

/*
 * ============================================================================
 * COMPILE-TIME LIMITS
 * ============================================================================
 *
 * Constants that describe the fixed-size parts of the types in
 * this header. These are compile-time limits, not runtime
 * configuration.
 */

#define BOWIE_ADDR_MAX_LEN     16
#define BOWIE_IPV4_LEN          4
#define BOWIE_IPV6_LEN         16
#define BOWIE_MAX_PEERS      1024
#define BOWIE_MAX_GRANTS      256
#define BOWIE_MAX_SESSIONS    512



/*
 * ============================================================================
 * TYPE HELPERS
 * ============================================================================
 *
 * Small value operations on the types in this header. These are
 * the operations that every layer needs and that would otherwise
 * be reimplemented in each layer.
 *
 * The helpers are grouped by type. Each group follows the same
 * shape:
 *
 *   _clear()    zero the value
 *   _is_zero()  true when every byte is zero (IDs)
 *   _is_set()   true when the value is not the unset state
 *               (addresses; the unset state is BOWIE_AF_UNSPEC)
 *   _equal()    true when two values are equal
 *
 * No helper here allocates, performs I/O, or depends on a
 * platform. Every one is a pure value operation that can be
 * inlined by the compiler.
 *
 * Helpers whose semantics depend on a policy decision (hashing,
 * ordering, string formatting, address classification) are NOT
 * declared here. They will be added by the layer that owns the
 * policy, when that policy is decided.
 */

/*
 * ----------------------------------------------------------------------------
 * Spans and strings
 * ----------------------------------------------------------------------------
 */

/*
 * True when the span has zero length.
 *
 * A span with data == NULL and len == 0 is empty.
 * A span with data != NULL and len == 0 is also empty.
 */
int bowie_span_is_empty(bowie_span_t span);

/*
 * True when two spans have the same length and the same bytes.
 *
 * Two empty spans are equal regardless of their data pointers.
 */
int bowie_span_equal(bowie_span_t a, bowie_span_t b);

/*
 * True when the string slice has zero length.
 */
int bowie_str_is_empty(bowie_str_t str);

/*
 * True when two string slices have the same length and the same
 * bytes.
 *
 * The comparison is byte-wise, not locale-aware. No NUL
 * terminator is required or assumed.
 */
int bowie_str_equal(bowie_str_t a, bowie_str_t b);

/*
 * ----------------------------------------------------------------------------
 * Buffers
 * ----------------------------------------------------------------------------
 */

/*
 * Reset a buffer to empty. The capacity is not changed; only
 * the used length is reset.
 *
 * Passing NULL is a no-op.
 */
void bowie_buf_clear(bowie_buf_t *buf);

/*
 * ----------------------------------------------------------------------------
 * Addresses
 * ----------------------------------------------------------------------------
 */

/*
 * Reset an address to the unset state. The family becomes
 * BOWIE_AF_UNSPEC, the address bytes become zero, and the port
 * becomes zero.
 *
 * Passing NULL is a no-op.
 */
void bowie_addr_clear(bowie_addr_t *addr);

/*
 * True when the address is not in the unset state, that is,
 * when its family is a real address family.
 */
int bowie_addr_is_set(const bowie_addr_t *addr);

/*
 * True when two addresses have the same family, the same
 * address bytes, and the same port.
 *
 * Only the bytes meaningful for the family are compared. For
 * BOWIE_AF_INET, only the first four bytes are compared. For
 * BOWIE_AF_INET6, all sixteen are compared.
 *
 * Two unset addresses are equal.
 */
int bowie_addr_equal(const bowie_addr_t *a, const bowie_addr_t *b);

/*
 * ----------------------------------------------------------------------------
 * Peer ID
 * ----------------------------------------------------------------------------
 */

/*
 * Reset a peer ID to the all-zero state.
 *
 * Passing NULL is a no-op.
 */
void bowie_peer_id_clear(bowie_peer_id_t *id);

/*
 * True when every byte of the peer ID is zero.
 *
 * A NULL pointer is treated as zero, so the function returns
 * true for NULL.
 */
int bowie_peer_id_is_zero(const bowie_peer_id_t *id);

/*
 * True when two peer IDs have the same bytes.
 *
 * Two NULL pointers are equal. A NULL pointer and a zero ID are
 * equal.
 */
int bowie_peer_id_equal(const bowie_peer_id_t *a,
                        const bowie_peer_id_t *b);

/*
 * ----------------------------------------------------------------------------
 * Public ID
 * ----------------------------------------------------------------------------
 */

/*
 * Reset a public ID to the all-zero state.
 *
 * Passing NULL is a no-op.
 */
void bowie_public_id_clear(bowie_public_id_t *id);

/*
 * True when every byte of the public ID is zero.
 */
int bowie_public_id_is_zero(const bowie_public_id_t *id);

/*
 * True when two public IDs have the same bytes.
 */
int bowie_public_id_equal(const bowie_public_id_t *a,
                          const bowie_public_id_t *b);

/*
 * ----------------------------------------------------------------------------
 * Session ID
 * ----------------------------------------------------------------------------
 */

/*
 * Reset a session ID to the all-zero state.
 *
 * Passing NULL is a no-op.
 */
void bowie_session_id_clear(bowie_session_id_t *id);

/*
 * True when every byte of the session ID is zero.
 */
int bowie_session_id_is_zero(const bowie_session_id_t *id);

/*
 * True when two session IDs have the same bytes.
 */
int bowie_session_id_equal(const bowie_session_id_t *a,
                           const bowie_session_id_t *b);

/*
 * ----------------------------------------------------------------------------
 * Grant ID
 * ----------------------------------------------------------------------------
 */

/*
 * Reset a grant ID to the all-zero state.
 *
 * Passing NULL is a no-op.
 */
void bowie_grant_id_clear(bowie_grant_id_t *id);

/*
 * True when every byte of the grant ID is zero.
 */
int bowie_grant_id_is_zero(const bowie_grant_id_t *id);

/*
 * True when two grant IDs have the same bytes.
 */
int bowie_grant_id_equal(const bowie_grant_id_t *a,
                         const bowie_grant_id_t *b);



/*
 * ============================================================================
 * END OF PUBLIC TYPES
 * ============================================================================
 */

#ifdef __cplusplus
}
#endif

#endif /* BOWIE_TYPES_H */
