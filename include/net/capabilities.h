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
 * BOWIE — CAPABILITIES
 * ============================================================================
 *
 * What a peer can do.
 *
 * A capability is a bit in a mask. A peer advertises the bits
 * it can perform. The three bits are:
 *
 *   SOURCE   — the peer can share Internet.
 *   CLIENT   — the peer can receive Internet.
 *   GATEWAY  — the peer can forward packets.
 *
 * A peer may have any combination of the three. A laptop that
 * both shares and receives has SOURCE | CLIENT. A router that
 * shares has SOURCE | GATEWAY. A phone that only receives has
 * CLIENT.
 *
 * The capability model replaces the older role model
 * (DONOR / RECIPIENT / BOTH). The role model was deprecated in
 * v2.1. This header is the public surface for the capability
 * model.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No ownership. Capability is what a peer can do; it is
 *     not who owns the peer.
 *   - No permission. Capability is a self-description; it is
 *     not authorization. A peer that advertises SOURCE still
 *     needs a grant to serve a specific CLIENT.
 *   - No policy. The header does not decide which combination
 *     of capabilities is valid for a deployment mode. That is
 *     the configuration module's concern.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * The capability enum is declared in bowie/config.h, because
 * the configuration structure carries a capability mask. This
 * header does not redeclare the enum; it includes config.h and
 * adds the operations that are specific to the capability
 * model.
 *
 * The operations are:
 *
 *   - Name lookup: turn a capability bit into a stable string
 *     for a log line or a diagnostic.
 *
 *   - String parsing: turn a comma-separated list of names
 *     into a mask.
 *
 *   - String formatting: turn a mask into a comma-separated
 *     list of names.
 *
 * The names are the same as the enum constants without the
 * BOWIE_CAP_ prefix: "source", "client", "gateway". The names
 * are lower-case.
 *
 * A parse that encounters an unknown name reports the number
 * of unknown names through an out pointer and continues. This
 * lets a caller accept a list with unknown names and report
 * them, rather than rejecting the whole list.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <stdint.h>                    uint32_t
 *   <stddef.h>                    size_t
 *   "bowie/config.h"              bowie_cap_t, BOWIE_CAP_*
 *   "bowie/err.h"                 bowie_error_t
 * ============================================================================
 */

#ifndef BOWIE_NET_CAPABILITIES_H
#define BOWIE_NET_CAPABILITIES_H

#include <stdint.h>
#include <stddef.h>

#include "bowie/config.h"
#include "bowie/err.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ============================================================================
 * NAME LOOKUP
 * ============================================================================
 */

/*
 * Return a stable, lower-case name for a single capability.
 *
 * The returned pointer is to a static string and must not be
 * freed. The string is never NULL.
 *
 * A mask with more than one bit set returns "multiple". A mask
 * of zero returns "none". An unknown bit returns "unknown".
 *
 * For a caller that wants the name of one bit, pass a mask
 * with exactly one bit. For a caller that wants a list of
 * names, use bowie_cap_mask_to_string.
 */
const char *bowie_cap_name(uint32_t mask);

/*
 * ============================================================================
 * STRING FORMATTING
 * ============================================================================
 */

/*
 * Format a capability mask into a comma-separated list of
 * names.
 *
 * The names are written in a fixed order: source, client,
 * gateway. The list is written into the caller's buffer and is
 * NUL-terminated. A buffer that is too small is filled up to
 * cap - 1 bytes and NUL-terminated.
 *
 * A mask of zero is written as "none".
 *
 * Returns the number of bytes that would have been written,
 * excluding the terminator, following snprintf semantics.
 *
 * Passing NULL for buf returns 0.
 */
int bowie_cap_mask_to_string(uint32_t mask, char *buf, size_t cap);

/*
 * ============================================================================
 * STRING PARSING
 * ============================================================================
 */

/*
 * Parse a comma-separated list of capability names into a
 * mask.
 *
 * The names are matched case-insensitively. The recognized
 * names are "source", "client", "gateway". The name "none"
 * matches a zero mask. Whitespace around a name is ignored.
 *
 * An empty string parses as BOWIE_CAP_NONE.
 *
 * An unknown name is counted but not rejected: the function
 * continues parsing the rest of the list and reports the
 * number of unknown names through out_unknown. A caller that
 * wants strict behavior checks out_unknown after the call and
 * rejects the mask if it is non-zero.
 *
 * Returns BOWIE_OK on success, with *out filled and
 *   *out_unknown set to the number of unknown names.
 * Returns BOWIE_ERR_NULL_ARG if str or out is NULL.
 *
 * A NULL out_unknown is allowed; the count is discarded.
 */
bowie_error_t bowie_cap_mask_from_string(const char *str,
                                          uint32_t *out,
                                          size_t *out_unknown);

/*
 * ============================================================================
 * MASK OPERATIONS
 * ============================================================================
 */

/*
 * The mask of all known capabilities.
 *
 * A caller that needs to check whether a mask contains only
 * known bits compares with this value.
 */
#define BOWIE_CAP_ALL \
    ( (uint32_t)BOWIE_CAP_SOURCE  \
    | (uint32_t)BOWIE_CAP_CLIENT  \
    | (uint32_t)BOWIE_CAP_GATEWAY )

/*
 * True when every bit in the mask is a known capability.
 *
 * A mask of zero is valid. A mask with an unknown bit is not.
 */
int bowie_cap_mask_is_valid(uint32_t mask);

/*
 * ============================================================================
 * END OF CAPABILITIES
 * ============================================================================
 */

#ifdef __cplusplus
}
#endif

#endif /* BOWIE_NET_CAPABILITIES_H */
