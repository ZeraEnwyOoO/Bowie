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
 * BOWIE — ERROR TESTS
 * ============================================================================
 *
 * Unit tests for src/api/err.c.
 *
 * Every public function declared in bowie/err.h is covered here.
 *
 * The table tests assert properties of the table itself (codes
 * unique, names unique, first row is OK). These catch a mistake
 * that a per-function test would miss: a duplicate row that
 * makes the lookup return the wrong entry.
 *
 * ----------------------------------------------------------------------------
 * Dependencies
 * ----------------------------------------------------------------------------
 *
 *   <check.h>        test framework
 *   <errno.h>        errno constants
 *   <stdio.h>        snprintf
 *   <string.h>       strlen
 *   "bowie/err.h"    the unit under test
 * ============================================================================
 */

#include <check.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "bowie/err.h"
