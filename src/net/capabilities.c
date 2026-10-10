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
 * BOWIE — CAPABILITIES IMPLEMENTATION
 * ============================================================================
 *
 * Name lookup, string formatting, string parsing, and mask
 * validation for the capability model.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No ownership. Capability is what a peer can do; it is
 *     not who owns the peer.
 *   - No permission. Capability is a self-description; it is
 *     not authorization.
 *   - No policy. The header does not decide which combination
 *     of capabilities is valid for a deployment mode.
 *   - No allocation. Every function writes to a caller-supplied
 *     buffer.
 *   - No I/O. Nothing here reads or writes a file, a socket,
 *     or a log.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * The capability names are the enum constants without the
 * BOWIE_CAP_ prefix, in lower case:
 *
 *   "source"   for BOWIE_CAP_SOURCE
 *   "client"   for BOWIE_CAP_CLIENT
 *   "gateway"  for BOWIE_CAP_GATEWAY
 *   "none"     for a zero mask
 *
 * The order of the names in the formatted string is fixed:
 * source, client, gateway. The order is chosen to match the
 * order in the design document and to match the order in
 * which the enum constants are declared.
 *
 * The parser is case-insensitive. It accepts "Source",
 * "SOURCE", and "source" as the same name. Whitespace around
 * each name is ignored. An empty string parses as a zero
 * mask.
 *
 * An unknown name is counted but not rejected. The function
 * continues parsing the rest of the list. This lets a caller
 * accept a list with unknown names and report them, rather
 * than rejecting the whole list. A caller that wants strict
 * behavior checks the unknown count after the call.
 *
 * The parser does not allocate. It walks the input string in
 * place, using a small fixed-size buffer for each name.
 *
 * ----------------------------------------------------------------------------
 * Mask validity
 * ----------------------------------------------------------------------------
 *
 * A mask is valid when every bit is a known capability. A mask
 * with an unknown bit is invalid.
 *
 * bowie_cap_name() returns "unknown" for an invalid mask, even
 * when the mask also has multiple known bits. The distinction
 * between "multiple known bits" and "unknown bits" is
 * important: a caller that wants to know whether a mask is
 * usable must check bowie_cap_mask_is_valid() first, or must
 * treat "unknown" as an error.
 *
 * bowie_cap_mask_to_string() formats only the known bits. An
 * unknown bit is not named. A caller that needs to see the
 * unknown bits must format the raw mask itself.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <stdint.h>                    uint32_t
 *   <stddef.h>                    size_t
 *   <string.h>                    strlen, memcpy
 *   "bowie/config.h"              bowie_cap_t, BOWIE_CAP_*
 *   "bowie/err.h"                 error codes
 *   "bowie/net/capabilities.h"    the declarations
 * ============================================================================
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "bowie/config.h"
#include "bowie/err.h"
#include "net/capabilities.h"

/*
 * ============================================================================
 * INTERNAL — NAME TABLE
 * ============================================================================
 *
 * One row per known capability. The table is used for both
 * formatting (mask -> name) and parsing (name -> mask).
 *
 * The table is small and sorted by the bit value, not by the
 * name. Formatting walks the table in order; the order of the
 * output matches the order of the table.
 */

typedef struct cap_entry {
    uint32_t    bit;
    const char *name;
} cap_entry_t;

static const cap_entry_t g_cap_table[] = {
    { (uint32_t)BOWIE_CAP_SOURCE,  "source"  },
    { (uint32_t)BOWIE_CAP_CLIENT,  "client"  },
    { (uint32_t)BOWIE_CAP_GATEWAY, "gateway" },
};

#define CAP_TABLE_SIZE \
    (sizeof(g_cap_table) / sizeof(g_cap_table[0]))

/*
 * ============================================================================
 * INTERNAL — CASE-INSENSITIVE EQUALITY
 * ============================================================================
 *
 * Compare two NUL-terminated strings, ignoring the case of
 * ASCII letters.
 *
 * A non-letter byte is compared as-is. A letter byte is
 * compared after being converted to lower case by the ASCII
 * rule (a-z vs A-Z). The function does not use tolower(),
 * because tolower() is locale-dependent.
 *
 * Returns 1 when the strings are equal, 0 when they differ.
 */

static int str_case_equal(const char *a, const char *b)
{
    while (*a != '\0' && *b != '\0') {
        char ca = *a;
        char cb = *b;

        if (ca >= 'A' && ca <= 'Z') {
            ca = (char)(ca + ('a' - 'A'));
        }
        if (cb >= 'A' && cb <= 'Z') {
            cb = (char)(cb + ('a' - 'A'));
        }

        if (ca != cb) {
            return 0;
        }
        a++;
        b++;
    }
    return (*a == '\0' && *b == '\0') ? 1 : 0;
}

/*
 * ============================================================================
 * INTERNAL — COUNT SET BITS
 * ============================================================================
 *
 * Return the number of set bits in a mask. The implementation
 * is the standard bit-twiddling loop.
 */

static unsigned int count_bits(uint32_t mask)
{
    unsigned int n = 0u;
    while (mask != 0u) {
        n++;
        mask &= mask - 1u;
    }
    return n;
}

/*
 * ============================================================================
 * NAME LOOKUP
 * ============================================================================
 */

const char *bowie_cap_name(uint32_t mask)
{
    /*
     * A mask with an unknown bit is "unknown", even when it
     * also has one or more known bits. The unknown bit makes
     * the mask unusable, so the name reflects that.
     */
    if ((mask & ~BOWIE_CAP_ALL) != 0u) {
        return "unknown";
    }

    /*
     * A mask of zero is "none".
     */
    if (mask == 0u) {
        return "none";
    }

    /*
     * A mask with exactly one known bit is that bit's name.
     */
    for (size_t i = 0; i < CAP_TABLE_SIZE; i++) {
        if (mask == g_cap_table[i].bit) {
            return g_cap_table[i].name;
        }
    }

    /*
     * A valid mask with more than one bit is "multiple".
     */
    return "multiple";
}

/*
 * ============================================================================
 * STRING FORMATTING
 * ============================================================================
 */

int bowie_cap_mask_to_string(uint32_t mask, char *buf, size_t cap)
{
    if (buf == NULL || cap == 0u) {
        return 0;
    }

    /*
     * Walk the table in order. Each set bit is appended to the
     * output, separated by a comma and a space.
     *
     * The output follows snprintf semantics: the return value
     * is the number of bytes that would have been written,
     * excluding the terminator. A buffer that is too small is
     * filled up to cap - 1 bytes and NUL-terminated.
     *
     * Only known bits are named. An unknown bit is not
     * formatted; a caller that needs to see it must format
     * the raw mask itself.
     */
    size_t written = 0u;
    size_t needed  = 0u;
    int    first   = 1;

    for (size_t i = 0; i < CAP_TABLE_SIZE; i++) {
        if ((mask & g_cap_table[i].bit) == 0u) {
            continue;
        }

        const char *name = g_cap_table[i].name;
        size_t      len  = strlen(name);

        if (!first) {
            needed += 2u;  /* ", " */
            if (written + 2u < cap) {
                buf[written++] = ',';
                buf[written++] = ' ';
            }
        }
        first = 0;

        needed += len;
        if (written + len < cap) {
            memcpy(buf + written, name, len);
            written += len;
        } else {
            /*
             * The buffer is too small for the rest of the
             * name. Copy what fits and stop.
             */
            size_t room = cap - written - 1u;
            memcpy(buf + written, name, room);
            written = cap - 1u;
            break;
        }
    }

    /*
     * A mask of zero (or a mask with only unknown bits) is
     * "none". The mask is valid only when it has no unknown
     * bits; a mask with only unknown bits is unusual and is
     * formatted as "none" for lack of a better name.
     */
    if (needed == 0u) {
        const char *none = "none";
        size_t      len  = strlen(none);
        needed = len;

        if (written + len < cap) {
            memcpy(buf + written, none, len);
            written += len;
        } else {
            size_t room = cap - written - 1u;
            memcpy(buf + written, none, room);
            written = cap - 1u;
        }
    }

    buf[written] = '\0';
    return (int)needed;
}

/*
 * ============================================================================
 * STRING PARSING
 * ============================================================================
 */

/*
 * Parse one name and return the corresponding bit.
 *
 * The name is NUL-terminated. The function compares it, case
 * insensitively, to the names in the table. A name of "none"
 * is recognized and maps to zero.
 *
 * On success, *recognized is set to 1 and the bit is
 * returned. On failure, *recognized is set to 0 and the
 * return value is undefined.
 */

static uint32_t parse_one_name(const char *name, int *recognized)
{
    *recognized = 0;

    if (str_case_equal(name, "none")) {
        *recognized = 1;
        return 0u;
    }

    for (size_t i = 0; i < CAP_TABLE_SIZE; i++) {
        if (str_case_equal(name, g_cap_table[i].name)) {
            *recognized = 1;
            return g_cap_table[i].bit;
        }
    }

    return 0u;
}

bowie_error_t bowie_cap_mask_from_string(const char *str,
                                          uint32_t *out,
                                          size_t *out_unknown)
{
    if (str == NULL || out == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }

    uint32_t mask    = 0u;
    size_t   unknown = 0u;

    const char *p = str;

    for (;;) {
        /* Skip leading whitespace. */
        while (*p == ' ' || *p == '\t') {
            p++;
        }

        /* Find the end of the name. */
        const char *start = p;
        while (*p != '\0' && *p != ',') {
            p++;
        }

        const char *end = p;

        /* Trim trailing whitespace. */
        while (end > start &&
               (end[-1] == ' ' || end[-1] == '\t')) {
            end--;
        }

        size_t len = (size_t)(end - start);

        /*
         * An empty segment is ignored. A trailing comma
         * produces an empty segment; it is not an error.
         */
        if (len == 0u) {
            if (*p == '\0') {
                break;
            }
            p++;
            continue;
        }

        /*
         * Copy the name into a small buffer and NUL-terminate
         * it. The buffer is large enough for the longest
         * known name; a name that is longer is counted as
         * unknown without being copied.
         */
        char name[16];
        if (len >= sizeof(name)) {
            unknown++;
        } else {
            memcpy(name, start, len);
            name[len] = '\0';

            int recognized = 0;
            uint32_t bit = parse_one_name(name, &recognized);
            if (recognized) {
                mask |= bit;
            } else {
                unknown++;
            }
        }

        if (*p == '\0') {
            break;
        }
        p++;
    }

    *out = mask;
    if (out_unknown != NULL) {
        *out_unknown = unknown;
    }
    return BOWIE_OK;
}

/*
 * ============================================================================
 * MASK VALIDATION
 * ============================================================================
 */

int bowie_cap_mask_is_valid(uint32_t mask)
{
    return ((mask & ~BOWIE_CAP_ALL) == 0u) ? 1 : 0;
}

/*
 * ============================================================================
 * END OF FILE
 * ============================================================================
 */
