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
 * BOWIE — VERSION
 * ============================================================================
 *
 * Compile-time version constants and runtime version access for
 * the Bowie library and applications.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No build metadata. Build type, build date, build commit,
 *     and build platform are not declared here. They require a
 *     build system that generates a header, and Bowie does not
 *     have one yet. When it does, those accessors will be added
 *     with their own contract.
 *   - No API version. The public API version is separate from
 *     the library version. If a distinct API version is needed,
 *     it will be declared with its own macros and accessors.
 *   - No network version negotiation. Comparing a local version
 *     to a remote one is a protocol concern. This header only
 *     compares local versions to compile-time or caller-supplied
 *     values.
 *   - No dynamic allocation. Every runtime accessor returns a
 *     value or a pointer to static storage.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * The version is expressed in three forms:
 *
 *   1. Numeric components (MAJOR, MINOR, PATCH) for compile-time
 *      comparison.
 *
 *   2. A packed numeric code for storage and wire use, where
 *      space matters.
 *
 *   3. A human-readable string for display.
 *
 * All three must stay in sync. The numeric code is derived from
 * the components by a fixed layout; the string is the canonical
 * human-readable form.
 *
 * The version follows Semantic Versioning 2.0.0 for the public
 * release series:
 *
 *   MAJOR — incompatible API changes.
 *   MINOR — backwards-compatible additions.
 *   PATCH — backwards-compatible fixes.
 *
 * Pre-release and build-metadata suffixes are not encoded in the
 * numeric forms. A pre-release string, if used, is a build-time
 * concern.
 *
 * The macros provide compile-time access. The functions provide
 * runtime access to the same values, so that a consumer that
 * loads the library as a shared object can report the version it
 * is actually linked against, not the one it compiled against.
 *
 * The two forms must agree. The functions in version.c return
 * the same values as the macros. A test asserts this.
 *
 * ----------------------------------------------------------------------------
 * Version code layout
 * ----------------------------------------------------------------------------
 *
 * The packed code is a 32-bit unsigned integer:
 *
 *   bits 31..24   MAJOR   (8 bits)
 *   bits 23..16   MINOR   (8 bits)
 *   bits 15..8    PATCH   (8 bits)
 *   bits  7..0    reserved (8 bits, currently zero)
 *
 * This layout allows comparison with a single unsigned compare
 * and leaves a byte for future use (e.g. a pre-release tag) that
 * can be added without changing the width of the field.
 *
 * The reserved byte is currently zero in all released versions.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <stdint.h>   uint32_t, uint8_t
 *   <stddef.h>   size_t
 *
 * This header is otherwise standalone. It does not include any
 * other Bowie header.
 * ============================================================================
 */

#ifndef BOWIE_VERSION_H
#define BOWIE_VERSION_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ============================================================================
 * VERSION COMPONENTS
 * ============================================================================
 */

#define BOWIE_VERSION_MAJOR  0
#define BOWIE_VERSION_MINOR  1
#define BOWIE_VERSION_PATCH  0

/*
 * ============================================================================
 * VERSION STRING
 * ============================================================================
 *
 * Canonical human-readable form. Must match the numeric
 * components above.
 */

#define BOWIE_VERSION_STRING "0.1.0"

/*
 * ============================================================================
 * VERSION CODE
 * ============================================================================
 *
 * Packed 32-bit numeric form. See the layout note in the file
 * header.
 *
 * The reserved byte is zero in this release.
 */

#define BOWIE_VERSION_CODE \
    ( ( (uint32_t)BOWIE_VERSION_MAJOR << 24 ) \
    | ( (uint32_t)BOWIE_VERSION_MINOR << 16 ) \
    | ( (uint32_t)BOWIE_VERSION_PATCH <<  8 ) \
    | ( (uint32_t)0u                         ) )

/*
 * ============================================================================
 * VERSION COMPARISON HELPERS
 * ============================================================================
 *
 * Compile-time helpers for conditional compilation. These are
 * macros, not functions, so they can be used in #if directives.
 *
 * BOWIE_VERSION_AT_LEAST(major, minor, patch)
 *   Expands to a constant expression that is true when the
 *   library version is greater than or equal to the given
 *   version.
 *
 * BOWIE_VERSION_BEFORE(major, minor, patch)
 *   Expands to a constant expression that is true when the
 *   library version is strictly less than the given version.
 *
 * Both helpers compare the packed code, so they are correct as
 * long as the layout above is respected.
 */

#define BOWIE_VERSION_AT_LEAST(major, minor, patch) \
    ( BOWIE_VERSION_CODE >= \
      ( ( (uint32_t)(major) << 24 ) \
      | ( (uint32_t)(minor) << 16 ) \
      | ( (uint32_t)(patch) <<  8 ) ) )

#define BOWIE_VERSION_BEFORE(major, minor, patch) \
    ( BOWIE_VERSION_CODE < \
      ( ( (uint32_t)(major) << 24 ) \
      | ( (uint32_t)(minor) << 16 ) \
      | ( (uint32_t)(patch) <<  8 ) ) )

/*
 * ============================================================================
 * VERSION STRUCT
 * ============================================================================
 *
 * A parsed version. The three components are stored separately so
 * that a caller can read them without unpacking a code.
 *
 * A parsed version with all three components zero is valid and
 * means "0.0.0", not "unset". There is no unset state; a caller
 * that needs one must track it separately.
 */

typedef struct bowie_version {
    uint8_t major;
    uint8_t minor;
    uint8_t patch;
} bowie_version_t;

/*
 * ============================================================================
 * RUNTIME ACCESSORS
 * ============================================================================
 *
 * The runtime version of the library that is actually linked.
 * These return the same values as the macros above when the
 * library is built from the same source tree.
 *
 * The distinction matters for a shared library: a consumer may
 * have been compiled against one version of the header and
 * linked against another version of the library. The macros
 * report the compile-time version; the functions report the
 * linked version.
 */

/*
 * Return the version string.
 *
 * The returned pointer is to a static string and must not be
 * freed. The string is never NULL.
 */
const char *bowie_version_string(void);

/*
 * Return the packed version code.
 */
uint32_t bowie_version_code(void);

/*
 * Return the major, minor, and patch components separately.
 *
 * Passing NULL for any output is a no-op for that output.
 */
void bowie_version_components(uint8_t *major,
                              uint8_t *minor,
                              uint8_t *patch);

/*
 * Return the parsed version.
 */
bowie_version_t bowie_version(void);

/*
 * ============================================================================
 * RUNTIME COMPARISON
 * ============================================================================
 */

/*
 * True when the linked library version is at least the given
 * version.
 */
int bowie_version_at_least(uint8_t major,
                           uint8_t minor,
                           uint8_t patch);

/*
 * True when the linked library version is strictly before the
 * given version.
 */
int bowie_version_before(uint8_t major,
                         uint8_t minor,
                         uint8_t patch);

/*
 * Compare two parsed versions.
 *
 * Returns:
 *   < 0  if a is older than b.
 *     0  if a and b are equal.
 *   > 0  if a is newer than b.
 */
int bowie_version_compare(bowie_version_t a, bowie_version_t b);

/*
 * ============================================================================
 * VERSION PARSING
 * ============================================================================
 */

/*
 * Parse a version string of the form "MAJOR.MINOR.PATCH".
 *
 * Leading and trailing whitespace is not accepted. A leading
 * 'v' or 'V' is accepted and skipped. Missing components are
 * treated as zero: "1" parses as 1.0.0, "1.2" parses as 1.2.0.
 *
 * Returns BOWIE_OK on success, with *out filled.
 *
 * Returns BOWIE_ERR_NULL_ARG if str or out is NULL.
 * Returns BOWIE_ERR_FORMAT if the string is not a valid version.
 * Returns BOWIE_ERR_RANGE if a component exceeds 255.
 *
 * The error codes come from bowie/err.h. This header does not
 * include err.h; version.c includes it. The function is
 * declared here with an int return type so that this header
 * stays free of the error contract.
 *
 * A caller that wants the typed error includes bowie/err.h and
 * casts the result. The values are defined to match.
 */
int bowie_version_parse(const char *str, bowie_version_t *out);

/*
 * ============================================================================
 * ABOUT
 * ============================================================================
 *
 * A one-line human-readable description of the library,
 * including its version and license. Intended for CLI
 * --version output and for log banners.
 *
 * The returned pointer is to a static string and must not be
 * freed. The string is never NULL.
 */
const char *bowie_about(void);

/*
 * ============================================================================
 * FUN ARRAY
 * ============================================================================
 *
 * Tiny collection of messages for developers who have been staring
 * at this code for too long.
 *
 * This array has zero effect on Bowie behavior.
 * It is not protocol data, user-facing security logic, or diagnostics.
 *
 * Basically: the code works. We are just having a little fun.
 *
 * ----------------------------------------------------------------------------
 * Boundary
 * ----------------------------------------------------------------------------
 *
 * These strings are:
 *   - not compiled into any wire format
 *   - not used by security, permission, or protocol code
 *   - not used by diagnostics that must be precise
 *   - optional at build time (BOWIE_NO_FUN)
 *
 * If you are reading this at 3 AM:
 *
 *   1. Go drink water.
 *   2. Check the logs.
 *   3. Do NOT blame the NAT yet.
 *   4. Yes, that packet really disappeared.
 *
 * — Bowie engineering department, allegedly
 * ============================================================================
 */

#ifndef BOWIE_NO_FUN
static const char *const bowie_fun[] = {
    "NAT said no.",
    "bro the packet vanished.",
    "P2P or pain.",
    "works on my machine.",
    "router chose violence.",
    "UDP doing UDP things.",
    "not a bug, just networking.",
};
#endif /* BOWIE_NO_FUN */

/*
 * ============================================================================
 * END OF PUBLIC VERSION
 * ============================================================================
 */

#ifdef __cplusplus
}
#endif

#endif /* BOWIE_VERSION_H */
