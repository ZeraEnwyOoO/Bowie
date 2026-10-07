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
 * BOWIE — ENDIAN IMPLEMENTATION
 * ============================================================================
 *
 * Byte-order conversion and fixed-width integer serialization.
 *
 * The implementation is byte-by-byte and does not depend on any
 * platform header. There is no unaligned access, and no
 * assumption about the host's byte order. This makes the same
 * source correct on every platform Bowie targets, including
 * platforms without htons/ntohs.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No allocation. Every function here operates on the
 *     caller's buffer or on a value.
 *   - No I/O. Nothing here reads or writes a file, a socket,
 *     or a log.
 *   - No bounds checking. A buffer passed to a put is assumed
 *     to have room for the value. A buffer passed to a get is
 *     assumed to have at least the required bytes. Callers that
 *     need bounds checking must provide it.
 *   - No detection of the host byte order. The functions do not
 *     need it; they are correct either way.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * The byte-swap functions are the only place a byte order
 * assumption would be made, and they make none. They reverse
 * the bytes of a value unconditionally.
 *
 * The host-conversion functions are defined in terms of the
 * byte-swap functions and a run-time check of the host byte
 * order. On a host that already uses the target order, the
 * conversion is a no-op. On a host that uses the other order,
 * the value is byte-swapped.
 *
 * The host byte order is detected by a portable check:
 *
 *   - If the bytes of the uint16_t value 0x0001, read as two
 *     bytes, are { 0x01, 0x00 }, the host is little-endian.
 *
 *   - Otherwise, the host is big-endian.
 *
 * The check is done once per call. The compiler folds it to a
 * constant on every target where it can prove the layout.
 *
 * The buffer functions are byte-by-byte. A put writes the
 * bytes in the target order and returns the number of bytes
 * written. A get reads the bytes in the target order and
 * returns the value. No unaligned access is performed, so the
 * pointer may be unaligned.
 *
 * The peek functions are aliases for the get functions. They
 * exist so that a caller can express intent; the compiler
 * typically inlines both to the same code.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <stdint.h>                    uint8_t, uint16_t, uint32_t,
 *                                 uint64_t
 *   <stddef.h>                    size_t
 *   "core/internal/endian.h"      the declarations
 * ============================================================================
 */

#include <stdint.h>
#include <stddef.h>

#include "core/internal/endian.h"

/*
 * ============================================================================
 * HOST BYTE ORDER DETECTION
 * ============================================================================
 *
 * A single boolean that is true on a little-endian host. The
 * check is a union read; the compiler folds it to a constant
 * on every target where it can prove the layout.
 *
 * The union is a standard C idiom for type punning. It is not
 * undefined behavior; the union has a single active member, and
 * the read is of the active member.
 */

static int host_is_little_endian(void)
{
    const union {
        uint16_t v;
        uint8_t  b[2];
    } u = { 0x0001u };

    return (u.b[0] == 0x01u) ? 1 : 0;
}

/*
 * ============================================================================
 * BYTE SWAP
 * ============================================================================
 *
 * Reverse the bytes of a value. These are the only primitive
 * byte-order operations in the file; everything else is built
 * from them or from byte-by-byte writes.
 */

uint16_t bowie_bswap16(uint16_t v)
{
    return (uint16_t)(((v & 0x00FFu) << 8)
                    | ((v & 0xFF00u) >> 8));
}

uint32_t bowie_bswap32(uint32_t v)
{
    return ((v & 0x000000FFu) << 24)
         | ((v & 0x0000FF00u) <<  8)
         | ((v & 0x00FF0000u) >>  8)
         | ((v & 0xFF000000u) >> 24);
}

uint64_t bowie_bswap64(uint64_t v)
{
    return ((v & 0x00000000000000FFull) << 56)
         | ((v & 0x000000000000FF00ull) << 40)
         | ((v & 0x0000000000FF0000ull) << 24)
         | ((v & 0x00000000FF000000ull) <<  8)
         | ((v & 0x000000FF00000000ull) >>  8)
         | ((v & 0x0000FF0000000000ull) >> 24)
         | ((v & 0x00FF000000000000ull) >> 40)
         | ((v & 0xFF00000000000000ull) >> 56);
}

/*
 * ============================================================================
 * HOST CONVERSION
 * ============================================================================
 *
 * The big-endian family.
 *
 * On a little-endian host, htobe is a byte swap and be16toh is
 * the same swap. On a big-endian host, both are no-ops.
 */

uint16_t bowie_htobe16(uint16_t v)
{
    return host_is_little_endian() ? bowie_bswap16(v) : v;
}

uint32_t bowie_htobe32(uint32_t v)
{
    return host_is_little_endian() ? bowie_bswap32(v) : v;
}

uint64_t bowie_htobe64(uint64_t v)
{
    return host_is_little_endian() ? bowie_bswap64(v) : v;
}

uint16_t bowie_be16toh(uint16_t v)
{
    return bowie_htobe16(v);
}

uint32_t bowie_be32toh(uint32_t v)
{
    return bowie_htobe32(v);
}

uint64_t bowie_be64toh(uint64_t v)
{
    return bowie_htobe64(v);
}

/*
 * The little-endian family.
 *
 * On a little-endian host, htole and le16toh are no-ops. On a
 * big-endian host, both are byte swaps.
 */

uint16_t bowie_htole16(uint16_t v)
{
    return host_is_little_endian() ? v : bowie_bswap16(v);
}

uint32_t bowie_htole32(uint32_t v)
{
    return host_is_little_endian() ? v : bowie_bswap32(v);
}

uint64_t bowie_htole64(uint64_t v)
{
    return host_is_little_endian() ? v : bowie_bswap64(v);
}

uint16_t bowie_le16toh(uint16_t v)
{
    return bowie_htole16(v);
}

uint32_t bowie_le32toh(uint32_t v)
{
    return bowie_htole32(v);
}

uint64_t bowie_le64toh(uint64_t v)
{
    return bowie_htole64(v);
}

/*
 * ============================================================================
 * BIG-ENDIAN BUFFER
 * ============================================================================
 *
 * Byte-by-byte, most significant byte first.
 */

size_t bowie_be16_put(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)((v >> 8) & 0xFFu);
    p[1] = (uint8_t)( v       & 0xFFu);
    return 2u;
}

size_t bowie_be32_put(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)((v >> 24) & 0xFFu);
    p[1] = (uint8_t)((v >> 16) & 0xFFu);
    p[2] = (uint8_t)((v >>  8) & 0xFFu);
    p[3] = (uint8_t)( v        & 0xFFu);
    return 4u;
}

size_t bowie_be64_put(uint8_t *p, uint64_t v)
{
    p[0] = (uint8_t)((v >> 56) & 0xFFu);
    p[1] = (uint8_t)((v >> 48) & 0xFFu);
    p[2] = (uint8_t)((v >> 40) & 0xFFu);
    p[3] = (uint8_t)((v >> 32) & 0xFFu);
    p[4] = (uint8_t)((v >> 24) & 0xFFu);
    p[5] = (uint8_t)((v >> 16) & 0xFFu);
    p[6] = (uint8_t)((v >>  8) & 0xFFu);
    p[7] = (uint8_t)( v        & 0xFFu);
    return 8u;
}

uint16_t bowie_be16_get(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8)
                    | ((uint16_t)p[1]     ));
}

uint32_t bowie_be32_get(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24)
         | ((uint32_t)p[1] << 16)
         | ((uint32_t)p[2] <<  8)
         | ((uint32_t)p[3]     );
}

uint64_t bowie_be64_get(const uint8_t *p)
{
    return ((uint64_t)p[0] << 56)
         | ((uint64_t)p[1] << 48)
         | ((uint64_t)p[2] << 40)
         | ((uint64_t)p[3] << 32)
         | ((uint64_t)p[4] << 24)
         | ((uint64_t)p[5] << 16)
         | ((uint64_t)p[6] <<  8)
         | ((uint64_t)p[7]     );
}

uint16_t bowie_be16_peek(const uint8_t *p)
{
    return bowie_be16_get(p);
}

uint32_t bowie_be32_peek(const uint8_t *p)
{
    return bowie_be32_get(p);
}

uint64_t bowie_be64_peek(const uint8_t *p)
{
    return bowie_be64_get(p);
}

/*
 * ============================================================================
 * LITTLE-ENDIAN BUFFER
 * ============================================================================
 *
 * Byte-by-byte, least significant byte first.
 */

size_t bowie_le16_put(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)( v       & 0xFFu);
    p[1] = (uint8_t)((v >> 8) & 0xFFu);
    return 2u;
}

size_t bowie_le32_put(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)( v        & 0xFFu);
    p[1] = (uint8_t)((v >>  8) & 0xFFu);
    p[2] = (uint8_t)((v >> 16) & 0xFFu);
    p[3] = (uint8_t)((v >> 24) & 0xFFu);
    return 4u;
}

size_t bowie_le64_put(uint8_t *p, uint64_t v)
{
    p[0] = (uint8_t)( v        & 0xFFu);
    p[1] = (uint8_t)((v >>  8) & 0xFFu);
    p[2] = (uint8_t)((v >> 16) & 0xFFu);
    p[3] = (uint8_t)((v >> 24) & 0xFFu);
    p[4] = (uint8_t)((v >> 32) & 0xFFu);
    p[5] = (uint8_t)((v >> 40) & 0xFFu);
    p[6] = (uint8_t)((v >> 48) & 0xFFu);
    p[7] = (uint8_t)((v >> 56) & 0xFFu);
    return 8u;
}

uint16_t bowie_le16_get(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[1] << 8)
                    | ((uint16_t)p[0]     ));
}

uint32_t bowie_le32_get(const uint8_t *p)
{
    return ((uint32_t)p[3] << 24)
         | ((uint32_t)p[2] << 16)
         | ((uint32_t)p[1] <<  8)
         | ((uint32_t)p[0]     );
}

uint64_t bowie_le64_get(const uint8_t *p)
{
    return ((uint64_t)p[7] << 56)
         | ((uint64_t)p[6] << 48)
         | ((uint64_t)p[5] << 40)
         | ((uint64_t)p[4] << 32)
         | ((uint64_t)p[3] << 24)
         | ((uint64_t)p[2] << 16)
         | ((uint64_t)p[1] <<  8)
         | ((uint64_t)p[0]     );
}

/*
 * ============================================================================
 * END OF FILE
 * ============================================================================
 */
