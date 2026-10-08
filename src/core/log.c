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
 * BOWIE — LOG IMPLEMENTATION
 * ============================================================================
 *
 * Internal logging: format a line, hand it to the installed
 * hook, discard it if no hook is installed.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No default output sink. Nothing is written to stdout or
 *     stderr by this file. A caller that wants log output must
 *     install a log hook through bowie_hooks_t.
 *   - No file I/O. Nothing here opens, reads, or writes a file.
 *   - No allocation. The format buffer is a member of the log
 *     context, which the caller owns.
 *   - No locale. Formatting is C-locale only.
 *   - No dynamic format strings. The format string is the one
 *     the caller passes; the parser in this file interprets a
 *     fixed set of conversion specifiers.
 *   - No timestamp. The module does not prepend a timestamp to
 *     a line. A caller that wants one passes it in the format
 *     string. This keeps the module free of a dependency on
 *     the time module and lets the caller choose between the
 *     monotonic and the wall clock.
 *   - No thread safety. A bowie_log_t is not safe to use from
 *     more than one thread at a time.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * A log context is a value type. It holds the current level, the
 * installed hook, and a format buffer. The engine creates one
 * context at startup and copies the level and the hook from the
 * bowie_hooks_t it was given. A test creates one on the stack.
 *
 * The format buffer is a fixed-size array. A line longer than
 * the buffer is truncated. The truncated line is still passed
 * to the hook; there is no marker appended. A marker would be
 * indistinguishable from a real ellipsis in the message, and a
 * caller that needs a longer line can split the message or
 * raise the buffer size. The truncation is silent by design:
 * the hook receives the bytes that fit, and the caller decides
 * whether that is enough.
 *
 * The format parser is small. It supports a fixed set of
 * conversion specifiers, listed in the file header of
 * core/internal/log.h. A specifier that is not in the set is
 * copied verbatim to the output. This is a deliberate choice:
 * the alternative, silently dropping the specifier, would make
 * a caller's mistake invisible.
 *
 * The parser is not printf. It does not support field widths,
 * precision, or length modifiers beyond the ones it documents.
 * It supports exactly the specifiers the module documents, and
 * nothing else. A caller that needs a richer format extends
 * the module.
 *
 * The emit function checks the level before formatting. A line
 * below the current level costs one comparison and one return.
 *
 * The parser uses snprintf for integer formatting. This is
 * slower than a hand-rolled integer-to-string, but the log path
 * is not hot: it runs once per event, not once per packet. The
 * portability and correctness of snprintf are worth more here
 * than the marginal speed of a hand-rolled converter. A caller
 * that needs to log at a very high rate can raise the level and
 * skip the formatting entirely.
 *
 * Thread safety: this file is not thread-safe. A caller that
 * shares a context between threads must serialize access. See
 * the thread safety note in core/internal/log.h.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <stdarg.h>                    va_list, va_start, va_end
 *   <stddef.h>                    size_t
 *   <string.h>                    memcpy, strlen
 *   <stdio.h>                     snprintf
 *   "bowie/config.h"              bowie_log_level_t
 *   "bowie/hooks.h"               bowie_log_hook_fn
 *   "core/internal/log.h"         the declarations
 * ============================================================================
 */

#include <stdarg.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>

#include "bowie/config.h"
#include "bowie/hooks.h"
#include "core/internal/log.h"

/*
 * ============================================================================
 * LEVEL NAMES
 * ============================================================================
 */

const char *bowie_log_level_name(bowie_log_level_t level)
{
    switch (level) {
    case BOWIE_LOG_NONE:  return "none";
    case BOWIE_LOG_ERROR: return "error";
    case BOWIE_LOG_WARN:  return "warn";
    case BOWIE_LOG_INFO:  return "info";
    case BOWIE_LOG_DEBUG: return "debug";
    case BOWIE_LOG_TRACE: return "trace";
    default:              return "unknown";
    }
}

char bowie_log_level_tag(bowie_log_level_t level)
{
    switch (level) {
    case BOWIE_LOG_NONE:  return '-';
    case BOWIE_LOG_ERROR: return 'E';
    case BOWIE_LOG_WARN:  return 'W';
    case BOWIE_LOG_INFO:  return 'I';
    case BOWIE_LOG_DEBUG: return 'D';
    case BOWIE_LOG_TRACE: return 'T';
    default:              return '?';
    }
}

/*
 * ============================================================================
 * INITIALIZATION
 * ============================================================================
 */

void bowie_log_init(bowie_log_t *log, const bowie_hooks_t *hooks,
                    bowie_log_level_t level)
{
    if (log == NULL) {
        return;
    }

    log->level = level;

    if (hooks != NULL) {
        log->hook     = hooks->log;
        log->userdata = hooks->log_userdata;
    } else {
        log->hook     = NULL;
        log->userdata = NULL;
    }

    log->line[0] = '\0';
}

void bowie_log_set_level(bowie_log_t *log, bowie_log_level_t level)
{
    if (log == NULL) {
        return;
    }
    log->level = level;
}

bowie_log_level_t bowie_log_get_level(const bowie_log_t *log)
{
    if (log == NULL) {
        return BOWIE_LOG_NONE;
    }
    return log->level;
}

int bowie_log_enabled(const bowie_log_t *log, bowie_log_level_t level)
{
    if (log == NULL) {
        return 0;
    }
    if (log->hook == NULL) {
        return 0;
    }
    return (log->level >= level) ? 1 : 0;
}

/*
 * ============================================================================
 * FORMAT PARSER
 * ============================================================================
 *
 * A small replacement for vsnprintf. It supports the specifiers
 * the module documents:
 *
 *   %s   string
 *   %u   unsigned int
 *   %d   int
 *   %llu unsigned long long
 *   %lld long long
 *   %zu  size_t
 *   %p   void *
 *   %x   unsigned int in lowercase hex
 *   %%   literal percent
 *
 * An unsupported specifier is copied verbatim. A trailing '%'
 * at the end of the format string is copied verbatim.
 *
 * The function writes at most cap - 1 bytes and NUL-terminates.
 * A line longer than the buffer is truncated. The truncation is
 * silent: there is no marker appended. The return value is the
 * number of bytes written, not including the terminator.
 */

static size_t append_str(char *buf, size_t pos, size_t cap,
                         const char *s)
{
    if (s == NULL) {
        s = "(null)";
    }
    while (*s != '\0' && pos + 1u < cap) {
        buf[pos++] = *s++;
    }
    return pos;
}

static size_t append_char(char *buf, size_t pos, size_t cap, char c)
{
    if (pos + 1u < cap) {
        buf[pos++] = c;
    }
    return pos;
}

static size_t format_line(char *buf, size_t cap,
                          const char *fmt, va_list ap)
{
    size_t pos = 0u;

    while (*fmt != '\0' && pos + 1u < cap) {
        if (*fmt != '%') {
            buf[pos++] = *fmt++;
            continue;
        }

        fmt++; /* skip '%' */

        if (*fmt == '\0') {
            /* Trailing '%'. */
            buf[pos++] = '%';
            break;
        }

        switch (*fmt) {
        case '%':
            buf[pos++] = '%';
            fmt++;
            break;

        case 's': {
            const char *s = va_arg(ap, const char *);
            pos = append_str(buf, pos, cap, s);
            fmt++;
            break;
        }

        case 'd': {
            int v = va_arg(ap, int);
            char tmp[32];
            (void)snprintf(tmp, sizeof(tmp), "%d", v);
            pos = append_str(buf, pos, cap, tmp);
            fmt++;
            break;
        }

        case 'u': {
            unsigned int v = va_arg(ap, unsigned int);
            char tmp[32];
            (void)snprintf(tmp, sizeof(tmp), "%u", v);
            pos = append_str(buf, pos, cap, tmp);
            fmt++;
            break;
        }

        case 'x': {
            unsigned int v = va_arg(ap, unsigned int);
            char tmp[32];
            (void)snprintf(tmp, sizeof(tmp), "%x", v);
            pos = append_str(buf, pos, cap, tmp);
            fmt++;
            break;
        }

        case 'p': {
            void *v = va_arg(ap, void *);
            char tmp[32];
            (void)snprintf(tmp, sizeof(tmp), "%p", v);
            pos = append_str(buf, pos, cap, tmp);
            fmt++;
            break;
        }

        case 'l': {
            /* %llu, %lld */
            if (fmt[1] == 'l' && fmt[2] == 'u') {
                unsigned long long v =
                    va_arg(ap, unsigned long long);
                char tmp[32];
                (void)snprintf(tmp, sizeof(tmp), "%llu", v);
                pos = append_str(buf, pos, cap, tmp);
                fmt += 3;
            } else if (fmt[1] == 'l' && fmt[2] == 'd') {
                long long v = va_arg(ap, long long);
                char tmp[32];
                (void)snprintf(tmp, sizeof(tmp), "%lld", v);
                pos = append_str(buf, pos, cap, tmp);
                fmt += 3;
            } else {
                /* Unsupported; copy verbatim. */
                buf[pos++] = '%';
                pos = append_char(buf, pos, cap, *fmt++);
            }
            break;
        }

        case 'z': {
            /* %zu */
            if (fmt[1] == 'u') {
                size_t v = va_arg(ap, size_t);
                char tmp[32];
                (void)snprintf(tmp, sizeof(tmp), "%zu", v);
                pos = append_str(buf, pos, cap, tmp);
                fmt += 2;
            } else {
                buf[pos++] = '%';
                pos = append_char(buf, pos, cap, *fmt++);
            }
            break;
        }

        default:
            /* Unsupported specifier; copy verbatim. */
            buf[pos++] = '%';
            pos = append_char(buf, pos, cap, *fmt++);
            break;
        }
    }

    buf[pos] = '\0';
    return pos;
}

/*
 * ============================================================================
 * EMIT
 * ============================================================================
 */

void bowie_log_emit(bowie_log_t *log, bowie_log_level_t level,
                    const char *fmt, ...)
{
    if (log == NULL || fmt == NULL) {
        return;
    }

    if (!bowie_log_enabled(log, level)) {
        return;
    }

    va_list ap;
    va_start(ap, fmt);
    (void)format_line(log->line, sizeof(log->line), fmt, ap);
    va_end(ap);

    log->hook(level, log->line, log->userdata);
}

/*
 * ============================================================================
 * END OF FILE
 * ============================================================================
 */
