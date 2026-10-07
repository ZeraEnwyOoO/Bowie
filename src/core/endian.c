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
 * BOWIE — ENDIAN (INTERNAL)
 * ============================================================================
 *
 * Byte-order conversion and fixed-width integer serialization.
 *
 * This header is internal to the Bowie library. It is not part
 * of the public API and is not installed. Functions declared
 * here are used by other internal modules that need to read or
 * write integers in a defined byte order.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No allocation. Every function here operates on the
 *     caller's buffer or on a value.
 *   - No I/O. Nothing here reads or writes a file, a socket,
 *     or a log.
 *   - No error handling. A buffer is assumed to be large
 *     enough for the value being written; a read is assumed to
 *     have at least the required bytes available. Callers that
 *     need bounds checking must provide it.
 *   - No floating point. Only 16-, 32-, and 64-bit unsigned
 *     integers are supported. A signed value is converted by
 *     the caller.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * The functions fall into three groups:
 *
 *   1. Byte swap. Reverse the byte order of a 16-, 32-, or
 *      64-bit value.
 *
 *   2. Host conversion. Convert between host byte order and a
 *      defined byte order (big-endian or little-endian). The
 *      conversion is a no-op on a host that already uses that
 *      order.
 *
 *   3. Buffer serialization. Write or read a fixed-width
 *      integer at a caller-supplied pointer, in a defined
 *      byte order. The pointer is advanced by the caller.
 *
 * The buffer functions are the ones other modules use. The
 * byte-swap and host-conversion functions exist so that the
 * buffer functions can be written portably.
 *
 * All buffer functions take a uint8_t pointer, not a void
 * pointer, so that the caller's intent is explicit. No function
 * here performs an unaligned access; every write and read is
 * byte by byte, so the pointer may be unaligned.
 *
 * Big-endian is the network byte order and is the default for
 * protocol serialization. Little-endian is provided because
 * some on-disk formats use it and because the round-trip tests
 * need a symmetric pair.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <stdint.h>   fixed-width integers
 *   <stddef.h>   size_t
 * ============================================================================
 */

#ifndef BOWIE_CORE_INTERNAL_ENDIAN_H
#define BOWIE_CORE_INTERNAL_ENDIAN_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ============================================================================
 * BYTE SWAP
 * ============================================================================
 *
 * Reverse the byte order of a value. These are the primitives
 * that the host-conversion functions build on.
 */

uint16_t bowie_bswap16(uint16_t v);
uint32_t bowie_bswap32(uint32_t v);
uint64_t bowie_bswap64(uint64_t v);

/*
 * ============================================================================
 * HOST CONVERSION
 * ============================================================================
 *
 * Convert between host byte order and a defined byte order.
 *
 * The htobe/htole family converts host to the named order.
 * The betoh/letoh family converts the named order to host.
 *
 * On a host that already uses the named order, the conversion
 * is a no-op. There is no way for a caller to detect this from
 * the API; the value is the same either way.
 */

uint16_t bowie_htobe16(uint16_t v);
uint32_t bowie_htobe32(uint32_t v);
uint64_t bowie_htobe64(uint64_t v);

uint16_t bowie_be16toh(uint16_t v);
uint32_t bowie_be32toh(uint32_t v);
uint64_t bowie_be64toh(uint64_t v);

uint16_t bowie_htole16(uint16_t v);
uint32_t bowie_htole32(uint32_t v);
uint64_t bowie_htole64(uint64_t v);

uint16_t bowie_le16toh(uint16_t v);
uint32_t bowie_le32toh(uint32_t v);
uint64_t bowie_le64toh(uint64_t v);

/*
 * ============================================================================
 * BIG-ENDIAN BUFFER
 * ============================================================================
 *
 * Write or read a fixed-width integer at a caller-supplied
 * pointer, in big-endian byte order.
 *
 * A put writes exactly the named number of bytes and returns
 * the number of bytes written (so the caller can advance a
 * cursor).
 *
 * A get reads exactly the named number of bytes and returns
 * the value. The pointer is not advanced; the caller advances
 * it.
 *
 * A peek reads the same way as a get but makes the
 * "does not advance" contract explicit in the name.
 */

size_t bowie_be16_put(uint8_t *p, uint16_t v);
size_t bowie_be32_put(uint8_t *p, uint32_t v);
size_t bowie_be64_put(uint8_t *p, uint64_t v);

uint16_t bowie_be16_get(const uint8_t *p);
uint32_t bowie_be32_get(const uint8_t *p);
uint64_t bowie_be64_get(const uint8_t *p);

uint16_t bowie_be16_peek(const uint8_t *p);
uint32_t bowie_be32_peek(const uint8_t *p);
uint64_t bowie_be64_peek(const uint8_t *p);

/*
 * ============================================================================
 * LITTLE-ENDIAN BUFFER
 * ============================================================================
 *
 * Same shape as the big-endian family, with little-endian byte
 * order.
 */

size_t bowie_le16_put(uint8_t *p, uint16_t v);
size_t bowie_le32_put(uint8_t *p, uint32_t v);
size_t bowie_le64_put(uint8_t *p, uint64_t v);

uint16_t bowie_le16_get(const uint8_t *p);
uint32_t bowie_le32_get(const uint8_t *p);
uint64_t bowie_le64_get(const uint8_t *p);

/*
 * ============================================================================
 * END OF INTERNAL ENDIAN
 * ============================================================================
 */

#ifdef __cplusplus
}
#endif

#endif /* BOWIE_CORE_INTERNAL_ENDIAN_H */
