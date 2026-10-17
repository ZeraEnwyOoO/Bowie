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
 * BOWIE — GATEWAY: IP FORWARDING (IMPLEMENTATION)
 * ============================================================================
 *
 * Implementation of the IP forwarding helpers declared in
 * gateway/ip_forward.h.
 *
 * The implementation reads and writes the sysctl files
 * directly. It does not call system() or popen(), which would
 * be slower and would depend on a shell.
 *
 * ----------------------------------------------------------------------------
 * What this file does NOT do
 * ----------------------------------------------------------------------------
 *
 *   - No routing.
 *   - No firewall.
 *   - No persistence.
 *
 * ----------------------------------------------------------------------------
 * Design notes
 * ----------------------------------------------------------------------------
 *
 * A sysctl file is a small text file. Reading it means opening
 * the file, reading one byte, and closing it. Writing it
 * means opening the file for writing and writing "0\n" or
 * "1\n".
 *
 * The file is closed before the function returns in every
 * path. A failure to open the file is mapped to a specific
 * error: ENOENT (file not found) becomes BOWIE_ERR_NOT_SUPPORTED,
 * EACCES and EPERM become BOWIE_ERR_PERMISSION, anything else
 * becomes BOWIE_ERR_NETWORK.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <errno.h>               errno
 *   <fcntl.h>               open, O_RDONLY, O_WRONLY
 *   <string.h>              memset
 *   <unistd.h>              read, write, close
 *   "bowie/err.h"           errors
 *   "gateway/ip_forward.h"  declarations
 * ============================================================================
 */

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include "bowie/err.h"
#include "gateway/ip_forward.h"

/*
 * ============================================================================
 * CONSTANTS
 * ============================================================================
 */

#define BOWIE_IP_FORWARD_PATH_V4 "/proc/sys/net/ipv4/ip_forward"
#define BOWIE_IP_FORWARD_PATH_V6 "/proc/sys/net/ipv6/conf/all/forwarding"

/*
 * ============================================================================
 * INTERNAL — READ
 * ============================================================================
 *
 * Read a single-byte value from a sysctl file. The file holds
 * "0\n" or "1\n"; any non-zero digit is treated as 1.
 */

static int read_value(const char *path)
{
    char  buf[8];
    int   fd;
    ssize_t n;

    fd = open(path, O_RDONLY);

    if (fd < 0) {
        if (errno == ENOENT) {
            return BOWIE_ERR_NOT_SUPPORTED;
        }
        if (errno == EACCES || errno == EPERM) {
            return BOWIE_ERR_PERMISSION;
        }
        return BOWIE_ERR_NETWORK;
    }

    memset(buf, 0, sizeof(buf));

    n = read(fd, buf, sizeof(buf) - 1);

    close(fd);

    if (n <= 0) {
        return BOWIE_ERR_NETWORK;
    }

    return (buf[0] == '1') ? 1 : 0;
}

/*
 * ============================================================================
 * INTERNAL — WRITE
 * ============================================================================
 *
 * Write a single-byte value to a sysctl file.
 */

static bowie_error_t write_value(const char *path, int enabled)
{
    char  buf[2];
    int   fd;
    ssize_t n;

    buf[0] = enabled ? '1' : '0';
    buf[1] = '\n';

    fd = open(path, O_WRONLY);

    if (fd < 0) {
        if (errno == ENOENT) {
            return BOWIE_ERR_NOT_SUPPORTED;
        }
        if (errno == EACCES || errno == EPERM) {
            return BOWIE_ERR_PERMISSION;
        }
        return BOWIE_ERR_NETWORK;
    }

    n = write(fd, buf, sizeof(buf));

    close(fd);

    if (n != (ssize_t)sizeof(buf)) {
        return BOWIE_ERR_NETWORK;
    }

    return BOWIE_OK;
}

/*
 * ============================================================================
 * CHECK
 * ============================================================================
 */

int bowie_ip_forward_is_enabled(void)
{
    return read_value(BOWIE_IP_FORWARD_PATH_V4);
}

int bowie_ip_forward_is_enabled_v6(void)
{
    return read_value(BOWIE_IP_FORWARD_PATH_V6);
}

/*
 * ============================================================================
 * SET
 * ============================================================================
 */

bowie_error_t bowie_ip_forward_set(int enabled)
{
    return write_value(BOWIE_IP_FORWARD_PATH_V4, enabled);
}

bowie_error_t bowie_ip_forward_set_v6(int enabled)
{
    return write_value(BOWIE_IP_FORWARD_PATH_V6, enabled);
}

/*
 * ============================================================================
 * CONVENIENCE
 * ============================================================================
 */

bowie_error_t bowie_ip_forward_enable(void)
{
    bowie_error_t rc;

    rc = bowie_ip_forward_set(1);
    if (rc != BOWIE_OK) {
        return rc;
    }

    return bowie_ip_forward_set_v6(1);
}

bowie_error_t bowie_ip_forward_disable(void)
{
    bowie_error_t rc;

    rc = bowie_ip_forward_set(0);
    if (rc != BOWIE_OK) {
        return rc;
    }

    return bowie_ip_forward_set_v6(0);
}

/*
 * ============================================================================
 * END OF GATEWAY IP FORWARDING IMPLEMENTATION
 * ============================================================================
 */
