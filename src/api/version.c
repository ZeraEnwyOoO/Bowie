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
 * BOWIE — VERSION IMPLEMENTATION
 * ============================================================================
 *
 * Runtime version access for the Bowie library.
 *
 * Every function here returns a value derived from the macros in
 * bowie/version.h. There is no other source of truth. If the
 * macros change, these functions change with them; a test
 * asserts the agreement.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No build metadata. Build commit, build date, build type,
 *     and build platform are not provided. They require a build
 *     system that generates a header, and Bowie does not have
 *     one yet.
 *   - No allocation. Every accessor returns a value or a
 *     pointer to static storage.
 *   - No global state. There is no version cache to initialize
 *     or tear down.
 *   - No I/O. No function here writes to a file, a socket, or
 *     a log.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * The runtime accessors exist so that a consumer linked against
 * a shared Bowie can report the version it is actually running,
 * not the version it was compiled against. The macros in the
 * header answer the compile-time question; these functions
 * answer the runtime question.
 *
 * The two must agree when the library is built from the same
 * source tree. A test in tests/unit/api/test_version.c asserts
 * that every runtime accessor matches its macro. If the two
 * ever disagree, the test fails.
 *
 * bowie_version_parse() is the only function here that can
 * fail. Its rules are documented in the header. The
 * implementation follows them exactly: no extra leniency, no
 * extra strictness.
 *
 * bowie_about() returns a compile-time constant string. There
 * is no runtime formatting, so there is no buffer to protect
 * and no allocation to fail.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <string.h>          strlen
 *   "bowie/version.h"   macros and declarations
 * ============================================================================
 */

#include <string.h>

#include "bowie/version.h"

/*
 * ============================================================================
 * RUNTIME ACCESSORS
 * ============================================================================
 */

const char *bowie_version_string(void)
{
    return BOWIE_VERSION_STRING;
}

uint32_t bowie_version_code(void)
{
    return (uint32_t)BOWIE_VERSION_CODE;
}

void bowie_version_components(uint8_t *major,
                              uint8_t *minor,
                              uint8_t *patch)
{
    if (major != NULL) {
        *major = (uint8_t)BOWIE_VERSION_MAJOR;
    }
    if (minor != NULL) {
        *minor = (uint8_t)BOWIE_VERSION_MINOR;
    }
    if (patch != NULL) {
        *patch = (uint8_t)BOWIE_VERSION_PATCH;
    }
}

bowie_version_t bowie_version(void)
{
    bowie_version_t v;
    v.major = (uint8_t)BOWIE_VERSION_MAJOR;
    v.minor = (uint8_t)BOWIE_VERSION_MINOR;
    v.patch = (uint8_t)BOWIE_VERSION_PATCH;
    return v;
}

/*
 * ============================================================================
 * RUNTIME COMPARISON
 * ============================================================================
 */

int bowie_version_at_least(uint8_t major,
                           uint8_t minor,
                           uint8_t patch)
{
    uint32_t want = ( (uint32_t)major << 24 )
                  | ( (uint32_t)minor << 16 )
                  | ( (uint32_t)patch <<  8 );

    return ((uint32_t)BOWIE_VERSION_CODE >= want) ? 1 : 0;
}

int bowie_version_before(uint8_t major,
                         uint8_t minor,
                         uint8_t patch)
{
    uint32_t want = ( (uint32_t)major << 24 )
                  | ( (uint32_t)minor << 16 )
                  | ( (uint32_t)patch <<  8 );

    return ((uint32_t)BOWIE_VERSION_CODE < want) ? 1 : 0;
}

int bowie_version_compare(bowie_version_t a, bowie_version_t b)
{
    /*
     * The packed code order matches the component order, so a
     * single unsigned compare is enough. The reserved byte is
     * zero for both, so it does not affect the result.
     */
    uint32_t ca = ( (uint32_t)a.major << 24 )
                | ( (uint32_t)a.minor << 16 )
                | ( (uint32_t)a.patch <<  8 );

    uint32_t cb = ( (uint32_t)b.major << 24 )
                | ( (uint32_t)b.minor << 16 )
                | ( (uint32_t)b.patch <<  8 );

    if (ca < cb) {
        return -1;
    }
    if (ca > cb) {
        return 1;
    }
    return 0;
}

/*
 * ============================================================================
 * VERSION PARSING
 * ============================================================================
 */

/*
 * Parse one decimal component.
 *
 * Advances *pos past the digits that were consumed. A component
 * with no digits is an error. A component larger than 255 is an
 * error.
 *
 * Returns BOWIE_OK on success, BOWIE_ERR_FORMAT if there are no
 * digits, BOWIE_ERR_RANGE if the value exceeds 255.
 */
static bowie_error_t parse_component(const char *str,
                                     size_t *pos,
                                     uint8_t *out)
{
    unsigned int value = 0u;
    size_t i = *pos;
    size_t digits = 0u;

    while (str[i] >= '0' && str[i] <= '9') {
        value = value * 10u + (unsigned int)(str[i] - '0');
        if (value > 255u) {
            return BOWIE_ERR_RANGE;
        }
        i++;
        digits++;
    }

    if (digits == 0u) {
        return BOWIE_ERR_FORMAT;
    }

    *pos = i;
    *out = (uint8_t)value;
    return BOWIE_OK;
}

bowie_error_t bowie_version_parse(const char *str,
                                  bowie_version_t *out)
{
    if (str == NULL || out == NULL) {
        return BOWIE_ERR_NULL_ARG;
    }

    size_t pos = 0u;

    /*
     * Optional leading 'v' or 'V'.
     */
    if (str[pos] == 'v' || str[pos] == 'V') {
        pos++;
    }

    /*
     * The first component is mandatory.
     */
    uint8_t major = 0u;
    bowie_error_t rc = parse_component(str, &pos, &major);
    if (rc != BOWIE_OK) {
        return rc;
    }

    uint8_t minor = 0u;
    uint8_t patch = 0u;

    /*
     * The second component is optional, but if a dot is
     * present, a component must follow.
     */
    if (str[pos] == '.') {
        pos++;
        rc = parse_component(str, &pos, &minor);
        if (rc != BOWIE_OK) {
            return rc;
        }

        /*
         * The third component is optional, with the same rule.
         */
        if (str[pos] == '.') {
            pos++;
            rc = parse_component(str, &pos, &patch);
            if (rc != BOWIE_OK) {
                return rc;
            }
        }
    }

    /*
     * Nothing may follow. This rejects trailing whitespace,
     * pre-release tags, and build metadata. A future version
     * that wants to accept those will extend the grammar in
     * the header first.
     */
    if (str[pos] != '\0') {
        return BOWIE_ERR_FORMAT;
    }

    out->major = major;
    out->minor = minor;
    out->patch = patch;
    return BOWIE_OK;
}

/*
 * ============================================================================
 * ABOUT
 * ============================================================================
 */

/*
 * The about string is built at compile time from the version
 * macros. There is no runtime formatting, so there is no buffer
 * to protect and no allocation to fail.
 *
 * The string is a single line: product name, version, purpose,
 * license. It is intended for CLI --version output and for log
 * banners.
 */
static const char g_bowie_about[] =
    "Bowie " BOWIE_VERSION_STRING
    " — P2P Internet Sharing Tool (GPL-3)";

const char *bowie_about(void)
{
    return g_bowie_about;
}

/*
 * ============================================================================
 * END OF FILE
 * ============================================================================
 */
