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
 * BOWIE — POSIX PLATFORM LOG
 * ============================================================================
 *
 * Platform log writer for POSIX systems.
 *
 * The implementation writes to the system log facility. On
 * Linux and macOS this is syslog. On a system without syslog,
 * the function is a no-op.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No timestamp. The platform log facility adds its own.
 *   - No level tag. The caller supplies the complete line; the
 *     level is used only to pick the syslog priority.
 *   - No formatting. The line is written as-is.
 *   - No allocation. The function writes from the caller's
 *     buffer.
 *   - No buffering. Every call writes one line.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * The platform interface exposes a single function,
 * bowie_platform_log_write, that takes a level and a
 * NUL-terminated line. The level is one of the
 * BOWIE_PLATFORM_LOG_* constants defined in platform.h.
 *
 * The function maps the level to a syslog priority. The
 * mapping is:
 *
 *   BOWIE_PLATFORM_LOG_ERROR -> LOG_ERR
 *   BOWIE_PLATFORM_LOG_WARN  -> LOG_WARNING
 *   BOWIE_PLATFORM_LOG_INFO  -> LOG_INFO
 *   BOWIE_PLATFORM_LOG_DEBUG -> LOG_DEBUG
 *   BOWIE_PLATFORM_LOG_TRACE -> LOG_DEBUG
 *   BOWIE_PLATFORM_LOG_NONE  -> LOG_DEBUG
 *
 * The mapping for NONE is the same as for TRACE. A NONE level
 * should not reach the platform; the caller filters it out
 * before calling. If it does reach the platform, LOG_DEBUG is
 * the least surprising choice.
 *
 * The function calls openlog once, the first time it is used.
 * The openlog call uses the process name as the ident and
 * LOG_PID to include the process ID in each line. A second
 * call to openlog would replace the first, so the function
 * uses a guard to call openlog at most once.
 *
 * The guard is a plain int. It is not thread-safe. Two threads
 * that call the function at the same time may both call
 * openlog. In practice openlog is idempotent enough that the
 * double call is harmless; the function does not add a lock
 * for it.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <syslog.h>                    openlog, syslog, LOG_*
 *   "platform/platform.h"         the declarations
 * ============================================================================
 */

#include <syslog.h>

#include "platform/platform.h"

/*
 * ============================================================================
 * INTERNAL — LEVEL MAPPING
 * ============================================================================
 */

static int platform_level_to_syslog(int level)
{
    switch (level) {
    case BOWIE_PLATFORM_LOG_ERROR: return LOG_ERR;
    case BOWIE_PLATFORM_LOG_WARN:  return LOG_WARNING;
    case BOWIE_PLATFORM_LOG_INFO:  return LOG_INFO;
    case BOWIE_PLATFORM_LOG_DEBUG: return LOG_DEBUG;
    case BOWIE_PLATFORM_LOG_TRACE: return LOG_DEBUG;
    case BOWIE_PLATFORM_LOG_NONE:
    default:                       return LOG_DEBUG;
    }
}

/*
 * ============================================================================
 * INTERNAL — OPENLOG GUARD
 * ============================================================================
 *
 * openlog is called at most once. A second call would replace
 * the first, which is not what we want.
 *
 * The guard is a plain int. It is not thread-safe; see the
 * note in the file header.
 */

static int g_opened = 0;

static void ensure_opened(void)
{
    if (g_opened) {
        return;
    }
    openlog(NULL, LOG_PID, LOG_USER);
    g_opened = 1;
}

/*
 * ============================================================================
 * LOG WRITE
 * ============================================================================
 */

void bowie_platform_log_write(int level, const char *line)
{
    if (line == NULL) {
        return;
    }

    ensure_opened();

    /*
     * syslog takes a format string. The line is written as a
     * literal, not as a format, so the format is "%s" and
     * the line is the argument. This avoids a format-string
     * vulnerability if the line contains a '%'.
     */
    syslog(platform_level_to_syslog(level), "%s", line);
}

/*
 * ============================================================================
 * END OF FILE
 * ============================================================================
 */
