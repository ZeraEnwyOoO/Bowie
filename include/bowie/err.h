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
 * BOWIE — ERROR CODES
 * ============================================================================
 *
 * Central error taxonomy for the Bowie library and applications.
 *
 * Every public Bowie function that can fail returns bowie_error_t.
 * No function returns a raw errno value across the public API.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No error strings in the enum. Human-readable text lives in
 *     err.c, not in the header. The header stays data-only.
 *   - No dynamic allocation. The error context is a fixed-size
 *     ring, not a heap structure.
 *   - No threading semantics beyond what the caller provides.
 *     The last-error and context state are per-thread if the
 *     caller arranges it that way; this header does not impose
 *     one.
 *   - No protocol-level error codes. Wire error codes are a
 *     protocol concern and belong to the protocol layer, not to
 *     this taxonomy.
 *   - No dependency on any other Bowie header. This file is
 *     standalone.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * Error codes are grouped into ranges by class. The class of an
 * error is derivable from its numeric value without a lookup
 * table, so classification is cheap and stable.
 *
 * Ranges are deliberately spaced so that new codes can be added
 * to a class without renumbering existing codes. A gap in a
 * range is not an oversight; it is reserved space.
 *
 * The sentinel range exists so that "no error" and "unknown
 * error" are distinct values. A function that returns success
 * returns BOWIE_OK, not zero-as-success by accident.
 *
 * The taxonomy is intentionally smaller than a general-purpose
 * OS error table. Bowie only needs to distinguish failures that
 * change behavior:
 *
 *   - retryable vs fatal
 *   - benign vs serious
 *   - argument vs environment
 *
 * Anything more granular is a diagnostic concern and belongs in
 * the error context, not in the code.
 *
 * ----------------------------------------------------------------------------
 * Error class ranges
 * ----------------------------------------------------------------------------
 *
 *   GENERAL        -1   ..  -8
 *   ARGUMENT      -20   .. -27
 *   MEMORY        -30   .. -31
 *   NETWORK       -40   .. -52
 *   CRYPTO        -60   .. -67
 *   DHT           -80   .. -87
 *   TUNNEL       -100   .. -107
 *   PERMISSION   -120   .. -127
 *   GATEWAY      -140   .. -147
 *   STATE        -160   .. -167
 *   SENTINEL     -200
 *
 * Reserved gaps:
 *   -9   .. -19   (GENERAL extension)
 *   -28  .. -29   (ARGUMENT extension)
 *   -32  .. -39   (MEMORY extension)
 *   -53  .. -59   (NETWORK extension)
 *   -68  .. -79   (CRYPTO / future class)
 *   -88  .. -99   (DHT extension)
 *  -108  .. -119  (TUNNEL extension)
 *  -128  .. -139  (PERMISSION extension)
 *  -148  .. -159  (GATEWAY extension)
 *  -168  .. -199  (STATE extension)
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   None. This header is standalone.
 * ============================================================================
 */

#ifndef BOWIE_ERR_H
#define BOWIE_ERR_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ============================================================================
 * ERROR TYPE
 * ============================================================================
 *
 * All public Bowie functions that can fail return bowie_error_t.
 * The type is signed so that BOWIE_OK is a distinct zero value
 * and negative values are unambiguous errors.
 */

typedef int bowie_error_t;

/*
 * ============================================================================
 * SUCCESS
 * ============================================================================
 *
 * BOWIE_OK is the only success value. A function that returns
 * BOWIE_OK must have completed the operation it promised.
 *
 * A function must not return BOWIE_OK and also set an error
 * context. The two are mutually exclusive.
 */

#define BOWIE_OK 0

/*
 * ============================================================================
 * GENERAL
 * ============================================================================
 *
 * Failures that do not fit a more specific class. Prefer a
 * specific class when one applies.
 */

#define BOWIE_ERR_GENERAL          (-1)
#define BOWIE_ERR_NOT_IMPLEMENTED  (-2)
#define BOWIE_ERR_NOT_SUPPORTED    (-3)
#define BOWIE_ERR_INTERNAL         (-4)
#define BOWIE_ERR_UNKNOWN          (-5)
#define BOWIE_ERR_CANCELLED        (-6)
#define BOWIE_ERR_ALREADY_EXISTS   (-7)
#define BOWIE_ERR_NOT_FOUND        (-8)

/*
 * ============================================================================
 * ARGUMENT
 * ============================================================================
 *
 * Programming errors. These indicate a bug in the caller, not a
 * problem with the environment.
 */

#define BOWIE_ERR_INVAL            (-20)
#define BOWIE_ERR_NULL_ARG         (-21)
#define BOWIE_ERR_RANGE            (-22)
#define BOWIE_ERR_TYPE             (-23)
#define BOWIE_ERR_FORMAT           (-24)
#define BOWIE_ERR_TOO_SMALL        (-25)
#define BOWIE_ERR_TOO_LARGE        (-26)
#define BOWIE_ERR_NOT_TERMINATED   (-27)

/*
 * ============================================================================
 * MEMORY
 * ============================================================================
 */

#define BOWIE_ERR_NOMEM            (-30)
#define BOWIE_ERR_OVERFLOW         (-31)

/*
 * ============================================================================
 * NETWORK
 * ============================================================================
 *
 * Failures related to sockets, peers, and connectivity.
 */

#define BOWIE_ERR_NETWORK          (-40)
#define BOWIE_ERR_TIMEOUT          (-41)
#define BOWIE_ERR_CONN_REFUSED     (-42)
#define BOWIE_ERR_CONN_RESET       (-43)
#define BOWIE_ERR_HOST_UNREACH     (-44)
#define BOWIE_ERR_NET_UNREACH      (-45)
#define BOWIE_ERR_ADDR_IN_USE      (-46)
#define BOWIE_ERR_ADDR_NOT_AVAIL   (-47)
#define BOWIE_ERR_WOULD_BLOCK      (-48)
#define BOWIE_ERR_BROKEN_PIPE      (-49)
#define BOWIE_ERR_AGAIN            (-50)
#define BOWIE_ERR_SOCKET           (-51)
#define BOWIE_ERR_PROTOCOL         (-52)

/*
 * ============================================================================
 * CRYPTO
 * ============================================================================
 *
 * Failures from hash, cipher, signature, and keypair operations.
 */

#define BOWIE_ERR_CRYPTO           (-60)
#define BOWIE_ERR_KEY_INVALID      (-61)
#define BOWIE_ERR_SIGN_INVALID     (-62)
#define BOWIE_ERR_DECRYPT_FAILED   (-63)
#define BOWIE_ERR_ENCRYPT_FAILED   (-64)
#define BOWIE_ERR_HASH_MISMATCH    (-65)
#define BOWIE_ERR_KEY_EXPIRED      (-66)
#define BOWIE_ERR_KEY_MISSING      (-67)

/*
 * ============================================================================
 * DHT
 * ============================================================================
 *
 * Failures from DHT operations: routing, search, storage, token.
 */

#define BOWIE_ERR_DHT              (-80)
#define BOWIE_ERR_DHT_NO_NODE      (-81)
#define BOWIE_ERR_DHT_BAD_MESSAGE  (-82)
#define BOWIE_ERR_DHT_TIMEOUT      (-83)
#define BOWIE_ERR_DHT_TOKEN        (-84)
#define BOWIE_ERR_DHT_SECURITY     (-85)
#define BOWIE_ERR_DHT_STORAGE      (-86)
#define BOWIE_ERR_DHT_ROUTING      (-87)

/*
 * ============================================================================
 * TUNNEL
 * ============================================================================
 *
 * Failures from tun, packet, and mtu operations.
 */

#define BOWIE_ERR_TUNNEL           (-100)
#define BOWIE_ERR_TUN_OPEN         (-101)
#define BOWIE_ERR_TUN_READ         (-102)
#define BOWIE_ERR_TUN_WRITE        (-103)
#define BOWIE_ERR_PACKET_MALFORMED (-104)
#define BOWIE_ERR_PACKET_TOO_BIG   (-105)
#define BOWIE_ERR_MTU              (-106)
#define BOWIE_ERR_FRAGMENT         (-107)

/*
 * ============================================================================
 * PERMISSION
 * ============================================================================
 *
 * Failures from ownership, grant, session, and revoke operations.
 */

#define BOWIE_ERR_PERMISSION       (-120)
#define BOWIE_ERR_GRANT_INVALID    (-121)
#define BOWIE_ERR_GRANT_EXPIRED    (-122)
#define BOWIE_ERR_GRANT_REVOKED    (-123)
#define BOWIE_ERR_SESSION_INVALID  (-124)
#define BOWIE_ERR_SESSION_EXPIRED  (-125)
#define BOWIE_ERR_OWNER_MISMATCH   (-126)
#define BOWIE_ERR_SUBJECT_MISMATCH (-127)

/*
 * ============================================================================
 * GATEWAY
 * ============================================================================
 *
 * Failures from gateway, route, conntrack, and ip_forward.
 */

#define BOWIE_ERR_GATEWAY          (-140)
#define BOWIE_ERR_ROUTE            (-141)
#define BOWIE_ERR_CONNTRACK        (-142)
#define BOWIE_ERR_IP_FORWARD       (-143)
#define BOWIE_ERR_NAT              (-144)
#define BOWIE_ERR_FORWARD_DENIED   (-145)
#define BOWIE_ERR_QUOTA            (-146)
#define BOWIE_ERR_POLICY           (-147)

/*
 * ============================================================================
 * STATE
 * ============================================================================
 *
 * Failures from lifecycle and state machine operations.
 */

#define BOWIE_ERR_STATE            (-160)
#define BOWIE_ERR_STATE_INVALID    (-161)
#define BOWIE_ERR_STATE_TRANSITION (-162)
#define BOWIE_ERR_NOT_INITIALIZED  (-163)
#define BOWIE_ERR_ALREADY_STARTED  (-164)
#define BOWIE_ERR_NOT_STARTED      (-165)
#define BOWIE_ERR_ALREADY_STOPPED  (-166)
#define BOWIE_ERR_BUSY             (-167)

/*
 * ============================================================================
 * SENTINEL
 * ============================================================================
 *
 * Values that are not errors and not success. They exist so that
 * "no error recorded" and "unknown error" are distinct from any
 * real error code.
 */

#define BOWIE_ERR_NONE             (-200)

/*
 * ============================================================================
 * ERROR CLASS
 * ============================================================================
 *
 * The class of an error is derivable from its value without a
 * lookup table. Classification is used by callers that need to
 * decide whether to retry, abort, or ignore.
 */

typedef enum bowie_err_class {
    BOWIE_ERR_CLASS_OK         = 0,
    BOWIE_ERR_CLASS_GENERAL    = 1,
    BOWIE_ERR_CLASS_ARGUMENT   = 2,
    BOWIE_ERR_CLASS_MEMORY     = 3,
    BOWIE_ERR_CLASS_NETWORK    = 4,
    BOWIE_ERR_CLASS_CRYPTO     = 5,
    BOWIE_ERR_CLASS_DHT        = 6,
    BOWIE_ERR_CLASS_TUNNEL     = 7,
    BOWIE_ERR_CLASS_PERMISSION = 8,
    BOWIE_ERR_CLASS_GATEWAY    = 9,
    BOWIE_ERR_CLASS_STATE      = 10,
    BOWIE_ERR_CLASS_SENTINEL   = 11,
    BOWIE_ERR_CLASS_UNKNOWN    = 12,
} bowie_err_class_t;

/*
 * ============================================================================
 * PUBLIC API
 * ============================================================================
 *
 * These functions are declared here and implemented in err.c.
 *
 * The header declares the contract; err.c holds the data.
 */

/*
 * Return a stable, human-readable string for an error code.
 *
 * The returned pointer is to a static string and must not be
 * freed. The string is never NULL, even for unknown codes.
 */
const char *bowie_err_strerror(bowie_error_t err);

/*
 * Return a stable, human-readable name for an error code.
 *
 * The name is the macro identifier without the BOWIE_ERR_ prefix
 * where that is unambiguous, or the full macro name otherwise.
 * The returned pointer is to a static string and must not be
 * freed. The string is never NULL.
 */
const char *bowie_err_name(bowie_error_t err);

/*
 * Return the class of an error code.
 *
 * Unknown codes return BOWIE_ERR_CLASS_UNKNOWN. BOWIE_OK returns
 * BOWIE_ERR_CLASS_OK.
 */
bowie_err_class_t bowie_err_class(bowie_error_t err);

/*
 * Return the name of an error class.
 *
 * The returned pointer is to a static string and must not be
 * freed. The string is never NULL.
 */
const char *bowie_err_class_name(bowie_err_class_t cls);

/*
 * True when the error is a programming error in the caller.
 *
 * ARGUMENT-class errors are caller bugs. They are never
 * retryable.
 */
int bowie_err_is_argument(bowie_error_t err);

/*
 * True when the error is likely to succeed on retry without a
 * change to the caller's arguments.
 *
 * TIMEOUT, AGAIN, WOULD_BLOCK, and BUSY are retryable. Most
 * other errors are not.
 */
int bowie_err_is_retryable(bowie_error_t err);

/*
 * True when the error is fatal to the current operation and the
 * caller should stop, not retry with different arguments.
 *
 * NOMEM, INTERNAL, and STATE-class errors are fatal in this
 * sense.
 */
int bowie_err_is_fatal(bowie_error_t err);

/*
 * True when the error is benign: the caller may continue as if
 * the operation had succeeded with no effect.
 *
 * NOT_FOUND and ALREADY_EXISTS are benign. So is BOWIE_OK.
 */
int bowie_err_is_benign(bowie_error_t err);

/*
 * True when the value is BOWIE_OK.
 */
int bowie_err_is_ok(bowie_error_t err);

/*
 * True when the value is a real error code (negative and not
 * BOWIE_ERR_NONE).
 */
int bowie_err_is_error(bowie_error_t err);

/*
 * ============================================================================
 * LAST ERROR
 * ============================================================================
 *
 * A small per-call-site record of the most recent error. This is
 * a convenience for diagnostics, not a substitute for returning
 * errors properly.
 *
 * The last-error state is process-global unless the caller
 * arranges otherwise. Bowie does not promise thread-local
 * behavior for this state; a caller that needs per-thread
 * tracking should not rely on it.
 */

/*
 * Clear the last-error record.
 */
void bowie_err_clear_last(void);

/*
 * Record an error as the last error.
 *
 * Passing BOWIE_OK clears the record.
 */
void bowie_err_set_last(bowie_error_t err);

/*
 * Return the last recorded error, or BOWIE_ERR_NONE if no error
 * has been recorded since the last clear.
 */
bowie_error_t bowie_err_last(void);

/*
 * ============================================================================
 * ERROR CONTEXT
 * ============================================================================
 *
 * A fixed-size ring of short labels that describe where an error
 * occurred. The context is pushed by the function that detects
 * the error and read by the function that reports it.
 *
 * The context is a diagnostic aid. It is not part of the error
 * value and must not be used to make control-flow decisions.
 *
 * The ring is bounded. Pushing more labels than the ring can
 * hold discards the oldest labels. The most recent labels are
 * always retained.
 */

#define BOWIE_ERR_CONTEXT_MAX   16
#define BOWIE_ERR_CONTEXT_LABEL 32

/*
 * Clear the error context.
 */
void bowie_err_context_clear(void);

/*
 * Push a short label onto the context ring.
 *
 * A NULL label is a no-op. A label longer than
 * BOWIE_ERR_CONTEXT_LABEL is truncated.
 */
void bowie_err_context_push(const char *label);

/*
 * Pop the most recent label from the context ring.
 *
 * Popping an empty ring is a no-op.
 */
void bowie_err_context_pop(void);

/*
 * Return the number of labels currently in the context ring.
 */
unsigned int bowie_err_context_count(void);

/*
 * Return the label at the given index, where 0 is the oldest
 * label currently retained.
 *
 * Returns NULL if the index is out of range.
 */
const char *bowie_err_context_at(unsigned int index);

/*
 * Format the context ring into a caller-supplied buffer.
 *
 * The labels are joined with " -> " in oldest-to-newest order.
 * The output is always NUL-terminated when cap is greater than
 * zero. The return value is the number of bytes that would have
 * been written, excluding the terminator, following snprintf
 * semantics.
 */
int bowie_err_context_format(char *buf, unsigned int cap);

/*
 * ============================================================================
 * ERRNO MAPPING
 * ============================================================================
 *
 * Convert between bowie_error_t and the platform errno space.
 * Used at the boundary between Bowie code and platform code.
 *
 * The mapping is lossy in both directions. Unmapped errors map
 * to a generic value in the target space.
 */

/*
 * Map a platform errno value to a bowie_error_t.
 *
 * Returns BOWIE_OK for errno == 0. Returns a NETWORK-class error
 * for unrecognized non-zero values.
 */
bowie_error_t bowie_err_from_errno(int errno_value);

/*
 * Map a bowie_error_t to a platform errno value.
 *
 * Returns 0 for BOWIE_OK. Returns a generic errno for unmapped
 * errors.
 */
int bowie_err_to_errno(bowie_error_t err);

/*
 * ============================================================================
 * END OF PUBLIC API
 * ============================================================================
 */

#ifdef __cplusplus
}
#endif

#endif /* BOWIE_ERR_H */
