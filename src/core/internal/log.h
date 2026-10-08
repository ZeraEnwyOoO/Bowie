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
 * BOWIE — LOG (INTERNAL)
 * ============================================================================
 *
 * Internal logging for the Bowie library.
 *
 * This header is internal to the Bowie library. It is not part
 * of the public API and is not installed.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No default output sink. The library never writes to
 *     stdout or stderr. A caller that wants log output must
 *     install a log hook through bowie_hooks_t. With no hook
 *     installed, every log line is discarded.
 *   - No file I/O. Nothing here opens, reads, or writes a
 *     file.
 *   - No allocation. The format buffer is a fixed-size array
 *     inside the context. A line longer than the buffer is
 *     truncated.
 *   - No locale. Formatting is C-locale only.
 *   - No dynamic format strings. The format string is always
 *     a caller-supplied literal, and the arguments are the
 *     fixed set supported by this module. A caller that needs
 *     a different format must add it to this module.
 *   - No timestamp. The module does not prepend a timestamp
 *     to a line. A caller that wants one passes it as part of
 *     the format string. This keeps the module free of a
 *     dependency on the time module and lets the caller choose
 *     between the monotonic and the wall clock.
 *   - No thread safety. A bowie_log_t is not safe to use from
 *     more than one thread at a time. See the thread safety
 *     note below.
 *
 * ----------------------------------------------------------------------------
 * Thread safety
 * ----------------------------------------------------------------------------
 *
 * A bowie_log_t is NOT thread-safe. If multiple threads share a
 * log context, the caller must serialize access. The engine is
 * expected to provide either a per-thread context or an
 * external lock.
 *
 * This is a deliberate design decision. The log module is kept
 * simple: it has no lock, no atomic, and no per-thread state.
 * The engine, which knows how many threads it has and how they
 * are scheduled, is the right place to make the thread-safety
 * decision. A log module that tried to be thread-safe on its
 * own would either add a lock to every call (and pay for it
 * even in single-threaded programs) or add a hidden per-thread
 * context (and pay for TLS).
 *
 * The engine's contract is:
 *
 *   - One context per thread, or
 *   - One context shared by all threads, with an external lock
 *     around every call.
 *
 * A caller that does neither and calls the module from two
 * threads at once is a caller bug. The module does not detect
 * it.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * The log level is stored per-context, not globally. A context
 * is a small value type that a caller creates and passes to
 * every log call. The context carries:
 *
 *   - the current log level,
 *   - the installed log hook and its userdata,
 *   - a small fixed-size buffer used to format each line.
 *
 * A context is created with bowie_log_init. The engine creates
 * one context at startup and copies the level and the hook
 * from the bowie_hooks_t it was given. A module that has no
 * engine context (for example, an internal test) can create
 * its own context on the stack.
 *
 * The format is deliberately small. It supports a fixed set
 * of conversion specifiers:
 *
 *   %s   string
 *   %u   unsigned int
 *   %d   int
 *   %llu unsigned long long
 *   %lld long long
 *   %zu  size_t
 *   %p   void *
 *   %x   unsigned int in lowercase hex
 *   %%   a literal percent sign
 *
 * Any other specifier is copied verbatim. A caller that needs
 * a different format extends the module; the module does not
 * silently guess.
 *
 * The formatted line is passed to the hook, if one is
 * installed. The hook owns the string for the duration of the
 * call. The hook must not retain the pointer after the call
 * returns. This is documented in bowie/hooks.h as well.
 *
 * A log call that is below the current level is a no-op. The
 * check is done before formatting, so a level that is off
 * costs almost nothing.
 *
 * A line longer than the format buffer is truncated. The
 * truncated line is still passed to the hook; there is no
 * marker appended. A marker would be indistinguishable from a
 * real ellipsis in the message, and a caller that needs a
 * longer line can split the message or raise the buffer size.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <stdint.h>                    uint32_t
 *   <stddef.h>                    size_t
 *   "bowie/config.h"              bowie_log_level_t
 *   "bowie/hooks.h"               bowie_log_hook_fn
 * ============================================================================
 */

#ifndef BOWIE_CORE_INTERNAL_LOG_H
#define BOWIE_CORE_INTERNAL_LOG_H

#include <stdint.h>
#include <stddef.h>

#include "bowie/config.h"
#include "bowie/hooks.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ============================================================================
 * FORMAT BUFFER
 * ============================================================================
 *
 * The maximum length of a formatted log line, including the
 * NUL terminator. A longer line is truncated. The value is
 * small enough that a context can live on the stack in every
 * module that needs one.
 */

#define BOWIE_LOG_LINE_MAX 256

/*
 * ============================================================================
 * LOG CONTEXT
 * ============================================================================
 *
 * A small value type. It holds the current level, the
 * installed hook, and a format buffer.
 *
 * The buffer is a member of the context, not a global, so two
 * contexts can be used at once without interfering.
 *
 * Thread safety: a context is NOT safe to use from more than
 * one thread at a time. See the thread safety note in the file
 * header.
 */

typedef struct bowie_log {
    bowie_log_level_t level;
    bowie_log_hook_fn hook;
    void             *userdata;
    char              line[BOWIE_LOG_LINE_MAX];
} bowie_log_t;

/*
 * ============================================================================
 * INITIALIZATION
 * ============================================================================
 */

/*
 * Initialize a context.
 *
 * The level and the hook are taken from the given hooks set.
 * If the hooks set is NULL, the level is set to
 * BOWIE_LOG_NONE and the hook is cleared.
 *
 * Passing NULL for log is a no-op.
 */
void bowie_log_init(bowie_log_t *log, const bowie_hooks_t *hooks,
                    bowie_log_level_t level);

/*
 * Set the current level.
 *
 * Passing NULL for log is a no-op.
 */
void bowie_log_set_level(bowie_log_t *log, bowie_log_level_t level);

/*
 * Return the current level.
 *
 * A NULL log returns BOWIE_LOG_NONE.
 */
bowie_log_level_t bowie_log_get_level(const bowie_log_t *log);

/*
 * True when a message at the given level would be emitted.
 *
 * A message is emitted when the context's current level is
 * greater than or equal to the message's level, and the
 * context has a hook installed. A context with no hook
 * returns false for every level.
 */
int bowie_log_enabled(const bowie_log_t *log, bowie_log_level_t level);

/*
 * ============================================================================
 * EMIT
 * ============================================================================
 *
 * Format a line and pass it to the hook.
 *
 * The format string is a caller-supplied literal. The supported
 * conversion specifiers are listed in the file header. An
 * unsupported specifier is copied verbatim.
 *
 * A call below the current level is a no-op. A call with no
 * hook installed is a no-op.
 *
 * Passing NULL for log is a no-op.
 *
 * Thread safety: this function is NOT thread-safe. A caller
 * that shares a log context between threads must serialize
 * access. See the thread safety note in the file header.
 */
void bowie_log_emit(bowie_log_t *log, bowie_log_level_t level,
                    const char *fmt, ...)
#if defined(__GNUC__) || defined(__clang__)
    __attribute__((format(printf, 3, 4)))
#endif
    ;

/*
 * ============================================================================
 * LEVEL NAMES
 * ============================================================================
 */

/*
 * Return a stable, human-readable name for a level.
 *
 * The returned pointer is to a static string and must not be
 * freed. The string is never NULL.
 */
const char *bowie_log_level_name(bowie_log_level_t level);

/*
 * Return the single-character tag for a level. The tag is the
 * first letter of the name, upper case. For BOWIE_LOG_NONE it
 * is '-'.
 */
char bowie_log_level_tag(bowie_log_level_t level);

/*
 * ============================================================================
 * CONVENIENCE MACROS
 * ============================================================================
 *
 * The macros save the level check at the call site. A call
 * that is below the current level expands to nothing.
 */

#define BOWIE_LOG_ERROR(lg, ...) \
    bowie_log_emit((lg), BOWIE_LOG_ERROR, __VA_ARGS__)

#define BOWIE_LOG_WARN(lg, ...) \
    bowie_log_emit((lg), BOWIE_LOG_WARN, __VA_ARGS__)

#define BOWIE_LOG_INFO(lg, ...) \
    bowie_log_emit((lg), BOWIE_LOG_INFO, __VA_ARGS__)

#define BOWIE_LOG_DEBUG(lg, ...) \
    bowie_log_emit((lg), BOWIE_LOG_DEBUG, __VA_ARGS__)

#define BOWIE_LOG_TRACE(lg, ...) \
    bowie_log_emit((lg), BOWIE_LOG_TRACE, __VA_ARGS__)

/*
 * ============================================================================
 * END OF INTERNAL LOG
 * ============================================================================
 */

#ifdef __cplusplus
}
#endif

#endif /* BOWIE_CORE_INTERNAL_LOG_H */
