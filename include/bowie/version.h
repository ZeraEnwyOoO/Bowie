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
 * Compile-time version constants for the Bowie library and
 * applications.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No runtime version negotiation. The numeric macros and the
 *     string macro are compiled in; there is no API to query a
 *     peer's version through this header.
 *   - No build metadata. Build type, build date, build commit,
 *     and build platform are declared in the generated build
 *     headers, not here.
 *   - No API version. The public API version is separate from the
 *     library version; it is declared in the public API header.
 *   - No dependency on any other Bowie header. This file is
 *     standalone.
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
 * concern and lives in the generated build headers.
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
 *   None. This header is standalone.
 * ============================================================================
 */

#ifndef BOWIE_VERSION_H
#define BOWIE_VERSION_H

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
 * END OF FILE
 * ============================================================================
 */

#endif /* BOWIE_VERSION_H */
