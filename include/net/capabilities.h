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
 * Capability model for Bowie peers.
 *
 * A capability is a bit flag that describes what a peer can do
 * on the network: share Internet (SOURCE), receive it (CLIENT),
 * or forward packets (GATEWAY). Capabilities are advertised, not
 * assigned by role. A peer's deployment mode provides a preset,
 * but the caller may override it.
 *
 * The capability type and the functions that operate on it are
 * declared in bowie/config.h, because the configuration
 * structure carries a capability field and that field is part
 * of the locked public contract. This header exists so that the
 * net layer has a named owner for the capability model without
 * duplicating or moving the contract.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No new types. The capability type is bowie_cap_t, declared
 *     in bowie/config.h.
 *   - No new functions. The capability functions are declared in
 *     bowie/config.h.
 *   - No policy. This header does not decide what a peer may do;
 *     it exposes the model that the configuration and permission
 *     layers use.
 *   - No allocation. Nothing here allocates.
 *   - No I/O. Nothing here performs I/O.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * The capability model is intentionally small. Three flags cover
 * the three roles a Bowie peer can play. A future version may
 * add flags, but only when a real requirement exists; the flag
 * space is 32 bits wide and no reservation is needed today.
 *
 * A peer with no capabilities set (BOWIE_CAP_NONE) is valid. It
 * can participate in the network but cannot share, receive, or
 * forward. A configuration with no capabilities is normalized
 * from the deployment mode.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   "bowie/config.h"   bowie_cap_t, bowie_mode_t, bowie_cap_has,
 *                      bowie_cap_for_mode
 * ============================================================================
 */

#ifndef BOWIE_NET_CAPABILITIES_H
#define BOWIE_NET_CAPABILITIES_H

#include "bowie/config.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ============================================================================
 * CAPABILITY MODEL
 * ============================================================================
 *
 * The capability type and the functions that operate on it are
 * declared in bowie/config.h. They are re-exported through this
 * header so that the net layer can include a single header for
 * the capability model.
 *
 * The re-export is a documentation convenience, not a contract
 * change. A caller that includes only bowie/config.h gets the
 * same declarations.
 *
 * See bowie/config.h for:
 *
 *   bowie_cap_t          the capability flag type
 *   bowie_cap_has()      true when a mask contains a flag
 *   bowie_cap_for_mode() preset mask for a deployment mode
 *
 * The deployment mode type, bowie_mode_t, is also declared in
 * bowie/config.h and is the source of the preset.
 * ============================================================================
 */

#ifdef __cplusplus
}
#endif

#endif /* BOWIE_NET_CAPABILITIES_H */
