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
 * BOWIE — ERROR IMPLEMENTATION
 * ============================================================================
 *
 * Error strings, classification, last-error tracking, context
 * ring, and errno mapping for the Bowie error taxonomy.
 *
 * The taxonomy itself is declared in bowie/err.h. This file
 * provides the data and the behavior behind it.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No allocation. The error table is static. The context ring
 *     is a fixed-size array. There is no heap structure.
 *   - No I/O. Nothing here writes to a file, a socket, or a log.
 *   - No threading. The last-error and context state are
 *     process-global. A caller that needs per-thread state must
 *     provide its own; this file does not impose one.
 *   - No locale. The strings are ASCII, fixed, and not
 *     translated. A caller that wants localized text must
 *     translate on top.
 *   - No protocol error mapping. Wire error codes are a protocol
 *     concern; this file maps to and from the platform errno
 *     space only.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * The error table is the single source of truth for the name and
 * the string of each error code. Adding an error means adding one
 * row. Removing an error means removing one row. Nothing else
 * needs to change.
 *
 * The table is sorted by code so that a binary search is
 * possible. The search is still linear for now because the table
 * is small; the sort order is kept so that the search can be
 * swapped without reordering the data.
 *
 * The name returned by bowie_err_name() is the macro name
 * without the BOWIE_ERR_ prefix. For BOWIE_OK the name is "OK".
 * For an unknown code the name is "UNKNOWN".
 *
 * The string returned by bowie_err_strerror() is a short
 * human-readable description, not a full sentence. It is
 * intended for log lines and for debugger output, not for
 * display to an end user.
 *
 * The context ring is a fixed-size array of short labels. It is
 * a diagnostic aid: it records where an error was detected, not
 * what the error means. The ring is bounded; pushing more labels
 * than the ring can hold discards the oldest.
 *
 * The last-error record is a single value. It is convenience
 * state, not a contract. A caller that needs a reliable error
 * must use the return value of the function that failed, not
 * bowie_err_last().
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <errno.h>          errno constants
 *   <string.h>         strlen, memcpy, memset
 *   <stdio.h>          snprintf
 *   "bowie/err.h"      the taxonomy and the declarations
 * ============================================================================
 */

#include <errno.h>
#include <string.h>
#include <stdio.h>

#include "bowie/err.h"

/*
 * ============================================================================
 * ERROR TABLE
 * ============================================================================
 *
 * One row per public error code. The rows are kept in ascending
 * code order so that a future binary search can replace the
 * linear scan without reordering the data.
 *
 * A row is a triple: code, name (without the BOWIE_ERR_ prefix),
 * and a short human-readable string.
 */

typedef struct err_entry {
    bowie_error_t code;
    const char   *name;
    const char   *str;
} err_entry_t;

static const err_entry_t g_err_table[] = {
    /* Success. */
    { BOWIE_OK,
      "OK",
      "success" },

    /* General. */
    { BOWIE_ERR_GENERAL,
      "GENERAL",
      "general failure" },
    { BOWIE_ERR_NOT_IMPLEMENTED,
      "NOT_IMPLEMENTED",
      "not implemented" },
    { BOWIE_ERR_NOT_SUPPORTED,
      "NOT_SUPPORTED",
      "not supported" },
    { BOWIE_ERR_INTERNAL,
      "INTERNAL",
      "internal error" },
    { BOWIE_ERR_UNKNOWN,
      "UNKNOWN",
      "unknown error" },
    { BOWIE_ERR_CANCELLED,
      "CANCELLED",
      "operation cancelled" },
    { BOWIE_ERR_ALREADY_EXISTS,
      "ALREADY_EXISTS",
      "already exists" },
    { BOWIE_ERR_NOT_FOUND,
      "NOT_FOUND",
      "not found" },

    /* Argument. */
    { BOWIE_ERR_INVAL,
      "INVAL",
      "invalid argument" },
    { BOWIE_ERR_NULL_ARG,
      "NULL_ARG",
      "null argument" },
    { BOWIE_ERR_RANGE,
      "RANGE",
      "value out of range" },
    { BOWIE_ERR_TYPE,
      "TYPE",
      "wrong type" },
    { BOWIE_ERR_FORMAT,
      "FORMAT",
      "malformed input" },
    { BOWIE_ERR_TOO_SMALL,
      "TOO_SMALL",
      "buffer too small" },
    { BOWIE_ERR_TOO_LARGE,
      "TOO_LARGE",
      "value too large" },
    { BOWIE_ERR_NOT_TERMINATED,
      "NOT_TERMINATED",
      "string not terminated" },

    /* Memory. */
    { BOWIE_ERR_NOMEM,
      "NOMEM",
      "out of memory" },
    { BOWIE_ERR_OVERFLOW,
      "OVERFLOW",
      "arithmetic overflow" },

    /* Network. */
    { BOWIE_ERR_NETWORK,
      "NETWORK",
      "network failure" },
    { BOWIE_ERR_TIMEOUT,
      "TIMEOUT",
      "operation timed out" },
    { BOWIE_ERR_CONN_REFUSED,
      "CONN_REFUSED",
      "connection refused" },
    { BOWIE_ERR_CONN_RESET,
      "CONN_RESET",
      "connection reset" },
    { BOWIE_ERR_HOST_UNREACH,
      "HOST_UNREACH",
      "host unreachable" },
    { BOWIE_ERR_NET_UNREACH,
      "NET_UNREACH",
      "network unreachable" },
    { BOWIE_ERR_ADDR_IN_USE,
      "ADDR_IN_USE",
      "address already in use" },
    { BOWIE_ERR_ADDR_NOT_AVAIL,
      "ADDR_NOT_AVAIL",
      "address not available" },
    { BOWIE_ERR_WOULD_BLOCK,
      "WOULD_BLOCK",
      "operation would block" },
    { BOWIE_ERR_BROKEN_PIPE,
      "BROKEN_PIPE",
      "broken pipe" },
    { BOWIE_ERR_AGAIN,
      "AGAIN",
      "try again" },
    { BOWIE_ERR_SOCKET,
      "SOCKET",
      "socket failure" },
    { BOWIE_ERR_PROTOCOL,
      "PROTOCOL",
      "protocol error" },

    /* Crypto. */
    { BOWIE_ERR_CRYPTO,
      "CRYPTO",
      "crypto failure" },
    { BOWIE_ERR_KEY_INVALID,
      "KEY_INVALID",
      "invalid key" },
    { BOWIE_ERR_SIGN_INVALID,
      "SIGN_INVALID",
      "invalid signature" },
    { BOWIE_ERR_DECRYPT_FAILED,
      "DECRYPT_FAILED",
      "decryption failed" },
    { BOWIE_ERR_ENCRYPT_FAILED,
      "ENCRYPT_FAILED",
      "encryption failed" },
    { BOWIE_ERR_HASH_MISMATCH,
      "HASH_MISMATCH",
      "hash mismatch" },
    { BOWIE_ERR_KEY_EXPIRED,
      "KEY_EXPIRED",
      "key expired" },
    { BOWIE_ERR_KEY_MISSING,
      "KEY_MISSING",
      "key missing" },

    /* DHT. */
    { BOWIE_ERR_DHT,
      "DHT",
      "DHT failure" },
    { BOWIE_ERR_DHT_NO_NODE,
      "DHT_NO_NODE",
      "no DHT node" },
    { BOWIE_ERR_DHT_BAD_MESSAGE,
      "DHT_BAD_MESSAGE",
      "malformed DHT message" },
    { BOWIE_ERR_DHT_TIMEOUT,
      "DHT_TIMEOUT",
      "DHT operation timed out" },
    { BOWIE_ERR_DHT_TOKEN,
      "DHT_TOKEN",
      "DHT token rejected" },
    { BOWIE_ERR_DHT_SECURITY,
      "DHT_SECURITY",
      "DHT security check failed" },
    { BOWIE_ERR_DHT_STORAGE,
      "DHT_STORAGE",
      "DHT storage failure" },
    { BOWIE_ERR_DHT_ROUTING,
      "DHT_ROUTING",
      "DHT routing failure" },

    /* Tunnel. */
    { BOWIE_ERR_TUNNEL,
      "TUNNEL",
      "tunnel failure" },
    { BOWIE_ERR_TUN_OPEN,
      "TUN_OPEN",
      "failed to open tunnel device" },
    { BOWIE_ERR_TUN_READ,
      "TUN_READ",
      "tunnel read failed" },
    { BOWIE_ERR_TUN_WRITE,
      "TUN_WRITE",
      "tunnel write failed" },
    { BOWIE_ERR_PACKET_MALFORMED,
      "PACKET_MALFORMED",
      "malformed packet" },
    { BOWIE_ERR_PACKET_TOO_BIG,
      "PACKET_TOO_BIG",
      "packet too big" },
    { BOWIE_ERR_MTU,
      "MTU",
      "MTU failure" },
    { BOWIE_ERR_FRAGMENT,
      "FRAGMENT",
      "fragmentation failure" },

    /* Permission. */
    { BOWIE_ERR_PERMISSION,
      "PERMISSION",
      "permission failure" },
    { BOWIE_ERR_GRANT_INVALID,
      "GRANT_INVALID",
      "invalid grant" },
    { BOWIE_ERR_GRANT_EXPIRED,
      "GRANT_EXPIRED",
      "grant expired" },
    { BOWIE_ERR_GRANT_REVOKED,
      "GRANT_REVOKED",
      "grant revoked" },
    { BOWIE_ERR_SESSION_INVALID,
      "SESSION_INVALID",
      "invalid session" },
    { BOWIE_ERR_SESSION_EXPIRED,
      "SESSION_EXPIRED",
      "session expired" },
    { BOWIE_ERR_OWNER_MISMATCH,
      "OWNER_MISMATCH",
      "owner mismatch" },
    { BOWIE_ERR_SUBJECT_MISMATCH,
      "SUBJECT_MISMATCH",
      "subject mismatch" },

    /* Gateway. */
    { BOWIE_ERR_GATEWAY,
      "GATEWAY",
      "gateway failure" },
    { BOWIE_ERR_ROUTE,
      "ROUTE",
      "route failure" },
    { BOWIE_ERR_CONNTRACK,
      "CONNTRACK",
      "connection tracking failure" },
    { BOWIE_ERR_IP_FORWARD,
      "IP_FORWARD",
      "IP forwarding failure" },
    { BOWIE_ERR_NAT,
      "NAT",
      "NAT failure" },
    { BOWIE_ERR_FORWARD_DENIED,
      "FORWARD_DENIED",
      "forward denied" },
    { BOWIE_ERR_QUOTA,
      "QUOTA",
      "quota exceeded" },
    { BOWIE_ERR_POLICY,
      "POLICY",
      "policy violation" },

    /* State. */
    { BOWIE_ERR_STATE,
      "STATE",
      "state failure" },
    { BOWIE_ERR_STATE_INVALID,
      "STATE_INVALID",
      "invalid state" },
    { BOWIE_ERR_STATE_TRANSITION,
      "STATE_TRANSITION",
      "invalid state transition" },
    { BOWIE_ERR_NOT_INITIALIZED,
      "NOT_INITIALIZED",
      "not initialized" },
    { BOWIE_ERR_ALREADY_STARTED,
      "ALREADY_STARTED",
      "already started" },
    { BOWIE_ERR_NOT_STARTED,
      "NOT_STARTED",
      "not started" },
    { BOWIE_ERR_ALREADY_STOPPED,
      "ALREADY_STOPPED",
      "already stopped" },
    { BOWIE_ERR_BUSY,
      "BUSY",
      "resource busy" },

    /* Sentinel. */
    { BOWIE_ERR_NONE,
      "NONE",
      "no error recorded" },
};

#define ERR_TABLE_SIZE \
    (sizeof(g_err_table) / sizeof(g_err_table[0]))

/*
 * ============================================================================
 * TABLE LOOKUP
 * ============================================================================
 *
 * A linear scan. The table is small and kept in code order; a
 * binary search can replace this without reordering the data.
 */

static const err_entry_t *table_lookup(bowie_error_t err)
{
    for (size_t i = 0u; i < ERR_TABLE_SIZE; i++) {
        if (g_err_table[i].code == err) {
            return &g_err_table[i];
        }
    }
    return NULL;
}

/*
 * ============================================================================
 * STRINGS
 * ============================================================================
 */

const char *bowie_err_strerror(bowie_error_t err)
{
    const err_entry_t *e = table_lookup(err);
    if (e != NULL) {
        return e->str;
    }
    if (err < 0) {
        return "unknown error";
    }
    return "not an error";
}

const char *bowie_err_name(bowie_error_t err)
{
    const err_entry_t *e = table_lookup(err);
    if (e != NULL) {
        return e->name;
    }
    if (err < 0) {
        return "UNKNOWN";
    }
    return "OK";
}

/*
 * ============================================================================
 * CLASSIFICATION
 * ============================================================================
 */

bowie_err_class_t bowie_err_class(bowie_error_t err)
{
    if (err == BOWIE_OK) {
        return BOWIE_ERR_CLASS_OK;
    }
    if (err == BOWIE_ERR_NONE) {
        return BOWIE_ERR_CLASS_SENTINEL;
    }

    if (err >= BOWIE_ERR_GENERAL &&
        err <= BOWIE_ERR_NOT_FOUND) {
        return BOWIE_ERR_CLASS_GENERAL;
    }
    if (err >= BOWIE_ERR_INVAL &&
        err <= BOWIE_ERR_NOT_TERMINATED) {
        return BOWIE_ERR_CLASS_ARGUMENT;
    }
    if (err >= BOWIE_ERR_NOMEM &&
        err <= BOWIE_ERR_OVERFLOW) {
        return BOWIE_ERR_CLASS_MEMORY;
    }
    if (err >= BOWIE_ERR_NETWORK &&
        err <= BOWIE_ERR_PROTOCOL) {
        return BOWIE_ERR_CLASS_NETWORK;
    }
    if (err >= BOWIE_ERR_CRYPTO &&
        err <= BOWIE_ERR_KEY_MISSING) {
        return BOWIE_ERR_CLASS_CRYPTO;
    }
    if (err >= BOWIE_ERR_DHT &&
        err <= BOWIE_ERR_DHT_ROUTING) {
        return BOWIE_ERR_CLASS_DHT;
    }
    if (err >= BOWIE_ERR_TUNNEL &&
        err <= BOWIE_ERR_FRAGMENT) {
        return BOWIE_ERR_CLASS_TUNNEL;
    }
    if (err >= BOWIE_ERR_PERMISSION &&
        err <= BOWIE_ERR_SUBJECT_MISMATCH) {
        return BOWIE_ERR_CLASS_PERMISSION;
    }
    if (err >= BOWIE_ERR_GATEWAY &&
        err <= BOWIE_ERR_POLICY) {
        return BOWIE_ERR_CLASS_GATEWAY;
    }
    if (err >= BOWIE_ERR_STATE &&
        err <= BOWIE_ERR_BUSY) {
        return BOWIE_ERR_CLASS_STATE;
    }

    return BOWIE_ERR_CLASS_UNKNOWN;
}

const char *bowie_err_class_name(bowie_err_class_t cls)
{
    switch (cls) {
    case BOWIE_ERR_CLASS_OK:         return "OK";
    case BOWIE_ERR_CLASS_GENERAL:    return "GENERAL";
    case BOWIE_ERR_CLASS_ARGUMENT:   return "ARGUMENT";
    case BOWIE_ERR_CLASS_MEMORY:     return "MEMORY";
    case BOWIE_ERR_CLASS_NETWORK:    return "NETWORK";
    case BOWIE_ERR_CLASS_CRYPTO:     return "CRYPTO";
    case BOWIE_ERR_CLASS_DHT:        return "DHT";
    case BOWIE_ERR_CLASS_TUNNEL:     return "TUNNEL";
    case BOWIE_ERR_CLASS_PERMISSION: return "PERMISSION";
    case BOWIE_ERR_CLASS_GATEWAY:    return "GATEWAY";
    case BOWIE_ERR_CLASS_STATE:      return "STATE";
    case BOWIE_ERR_CLASS_SENTINEL:   return "SENTINEL";
    case BOWIE_ERR_CLASS_UNKNOWN:    return "UNKNOWN";
    default:                         return "UNKNOWN";
    }
}

int bowie_err_is_argument(bowie_error_t err)
{
    return (bowie_err_class(err) == BOWIE_ERR_CLASS_ARGUMENT) ? 1 : 0;
}

int bowie_err_is_retryable(bowie_error_t err)
{
    switch (err) {
    case BOWIE_ERR_TIMEOUT:
    case BOWIE_ERR_AGAIN:
    case BOWIE_ERR_WOULD_BLOCK:
    case BOWIE_ERR_BUSY:
        return 1;
    default:
        return 0;
    }
}

int bowie_err_is_fatal(bowie_error_t err)
{
    switch (err) {
    case BOWIE_ERR_NOMEM:
    case BOWIE_ERR_INTERNAL:
    case BOWIE_ERR_OVERFLOW:
        return 1;
    default:
        return (bowie_err_class(err) == BOWIE_ERR_CLASS_STATE)
               ? 1 : 0;
    }
}

int bowie_err_is_benign(bowie_error_t err)
{
    switch (err) {
    case BOWIE_OK:
    case BOWIE_ERR_NOT_FOUND:
    case BOWIE_ERR_ALREADY_EXISTS:
        return 1;
    default:
        return 0;
    }
}

int bowie_err_is_ok(bowie_error_t err)
{
    return (err == BOWIE_OK) ? 1 : 0;
}

int bowie_err_is_error(bowie_error_t err)
{
    if (err == BOWIE_OK || err == BOWIE_ERR_NONE) {
        return 0;
    }
    return (err < 0) ? 1 : 0;
}

/*
 * ============================================================================
 * LAST ERROR
 * ============================================================================
 */

static bowie_error_t g_last_err = BOWIE_ERR_NONE;

void bowie_err_clear_last(void)
{
    g_last_err = BOWIE_ERR_NONE;
}

void bowie_err_set_last(bowie_error_t err)
{
    g_last_err = (err == BOWIE_OK) ? BOWIE_ERR_NONE : err;
}

bowie_error_t bowie_err_last(void)
{
    return g_last_err;
}

/*
 * ============================================================================
 * ERROR CONTEXT
 * ============================================================================
 *
 * A fixed-size ring of short labels. Labels are stored in a
 * contiguous array of fixed-size slots. The ring keeps the most
 * recent labels; older labels are overwritten when the ring is
 * full.
 */

typedef struct err_context {
    char     labels[BOWIE_ERR_CONTEXT_MAX][BOWIE_ERR_CONTEXT_LABEL];
    unsigned int count;   /* number of valid labels */
    unsigned int head;    /* next slot to write */
} err_context_t;

static err_context_t g_ctx;

void bowie_err_context_clear(void)
{
    memset(&g_ctx, 0, sizeof(g_ctx));
}

void bowie_err_context_push(const char *label)
{
    if (label == NULL) {
        return;
    }

    /*
     * Copy up to BOWIE_ERR_CONTEXT_LABEL - 1 characters and
     * always terminate. The label is truncated if it is longer
     * than the slot.
     */
    char *slot = g_ctx.labels[g_ctx.head];
    size_t i = 0u;
    while (i < (BOWIE_ERR_CONTEXT_LABEL - 1u) && label[i] != '\0') {
        slot[i] = label[i];
        i++;
    }
    slot[i] = '\0';

    g_ctx.head = (g_ctx.head + 1u) % BOWIE_ERR_CONTEXT_MAX;
    if (g_ctx.count < BOWIE_ERR_CONTEXT_MAX) {
        g_ctx.count++;
    }
}

void bowie_err_context_pop(void)
{
    if (g_ctx.count == 0u) {
        return;
    }
    g_ctx.head = (g_ctx.head + BOWIE_ERR_CONTEXT_MAX - 1u)
                 % BOWIE_ERR_CONTEXT_MAX;
    g_ctx.count--;
}

unsigned int bowie_err_context_count(void)
{
    return g_ctx.count;
}

const char *bowie_err_context_at(unsigned int index)
{
    if (index >= g_ctx.count) {
        return NULL;
    }

    /*
     * The oldest valid label is at:
     *   (head - count + MAX) % MAX
     * The index-th label is that plus index.
     */
    unsigned int oldest = (g_ctx.head + BOWIE_ERR_CONTEXT_MAX
                           - g_ctx.count) % BOWIE_ERR_CONTEXT_MAX;
    unsigned int slot = (oldest + index) % BOWIE_ERR_CONTEXT_MAX;

    return g_ctx.labels[slot];
}

int bowie_err_context_format(char *buf, unsigned int cap)
{
    if (buf == NULL || cap == 0u) {
        return 0;
    }

    /*
     * Build the joined string manually so that the return
     * value follows snprintf semantics: the number of bytes
     * that would have been written, excluding the terminator.
     */
    size_t written = 0u;
    size_t needed = 0u;
    unsigned int n = g_ctx.count;

    for (unsigned int i = 0u; i < n; i++) {
        const char *label = bowie_err_context_at(i);
        size_t len = strlen(label);

        if (i > 0u) {
            needed += 4u;  /* " -> " */
            if (written + 1u < cap) {
                buf[written++] = ' ';
                buf[written++] = '-';
                buf[written++] = '>';
                buf[written++] = ' ';
            } else {
                written += 4u;
            }
        }

        needed += len;
        if (written + 1u < cap) {
            size_t room = cap - written - 1u;
            size_t copy = (len < room) ? len : room;
            memcpy(buf + written, label, copy);
            written += copy;
            if (copy < len) {
                /* Truncated. */
                written = cap - 1u;
                buf[written] = '\0';
                return (int)(needed + (len - copy));
            }
        } else {
            written += len;
        }
    }

    if (written < cap) {
        buf[written] = '\0';
    } else {
        buf[cap - 1u] = '\0';
        written = cap - 1u;
    }

    return (int)needed;
}

/*
 * ============================================================================
 * ERRNO MAPPING
 * ============================================================================
 */

bowie_error_t bowie_err_from_errno(int errno_value)
{
    switch (errno_value) {
    case 0:              return BOWIE_OK;
    case EINVAL:         return BOWIE_ERR_INVAL;
    case ENOMEM:         return BOWIE_ERR_NOMEM;
    case EAGAIN:         return BOWIE_ERR_AGAIN;
    case EWOULDBLOCK:    return BOWIE_ERR_WOULD_BLOCK;
    case ETIMEDOUT:      return BOWIE_ERR_TIMEOUT;
    case ECONNREFUSED:   return BOWIE_ERR_CONN_REFUSED;
    case ECONNRESET:     return BOWIE_ERR_CONN_RESET;
    case EHOSTUNREACH:   return BOWIE_ERR_HOST_UNREACH;
    case ENETUNREACH:    return BOWIE_ERR_NET_UNREACH;
    case EADDRINUSE:     return BOWIE_ERR_ADDR_IN_USE;
    case EADDRNOTAVAIL:  return BOWIE_ERR_ADDR_NOT_AVAIL;
    case EPIPE:          return BOWIE_ERR_BROKEN_PIPE;
    default:             return BOWIE_ERR_NETWORK;
    }
}

int bowie_err_to_errno(bowie_error_t err)
{
    switch (err) {
    case BOWIE_OK:               return 0;
    case BOWIE_ERR_INVAL:        return EINVAL;
    case BOWIE_ERR_NOMEM:        return ENOMEM;
    case BOWIE_ERR_AGAIN:        return EAGAIN;
    case BOWIE_ERR_WOULD_BLOCK:  return EWOULDBLOCK;
    case BOWIE_ERR_TIMEOUT:      return ETIMEDOUT;
    case BOWIE_ERR_CONN_REFUSED: return ECONNREFUSED;
    case BOWIE_ERR_CONN_RESET:   return ECONNRESET;
    case BOWIE_ERR_HOST_UNREACH: return EHOSTUNREACH;
    case BOWIE_ERR_NET_UNREACH:  return ENETUNREACH;
    case BOWIE_ERR_ADDR_IN_USE:  return EADDRINUSE;
    case BOWIE_ERR_ADDR_NOT_AVAIL: return EADDRNOTAVAIL;
    case BOWIE_ERR_BROKEN_PIPE:  return EPIPE;
    default:                     return EIO;
    }
}

/*
 * ============================================================================
 * END OF FILE
 * ============================================================================
 */
