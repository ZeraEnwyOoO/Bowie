 # ============================================================================
# Bowie — Makefile (Prototype Phase)
# ============================================================================
#
# Build system for the Bowie prototype. This file is used during
# phases 1-12 (see doc/PHASES.md). Once the prototype succeeds,
# the project switches to CMake for production.
#
# The switch is a build-system change only. Source files, headers,
# and tests are not touched during it.
#
# ----------------------------------------------------------------------------
# Targets
# ----------------------------------------------------------------------------
#
#   all        build the static library (default)
#   test       build and run the unit tests
#   clean      remove the build directory
#   help       print this help
#
# ----------------------------------------------------------------------------
# Variables
# ----------------------------------------------------------------------------
#
#   CC         C compiler (default: cc)
#   CFLAGS     compiler flags
#   LDFLAGS    linker flags
#   LDLIBS     libraries to link
#   V          verbose (V=1 to show full compile commands)
#
# ----------------------------------------------------------------------------
# Layout
# ----------------------------------------------------------------------------
#
#   include/   public headers
#   src/       source files and internal headers
#   tests/     unit and integration tests
#   build/     build output (gitignored)
#
# ============================================================================

# ----------------------------------------------------------------------------
# Toolchain
# ----------------------------------------------------------------------------

CC      ?= cc
AR      ?= ar
RANLIB  ?= ranlib

# ----------------------------------------------------------------------------
# Flags
# ----------------------------------------------------------------------------

# Strict, portable, C11. Werror is on for the prototype so that
# a warning cannot be ignored by accident.
CFLAGS  := -std=c11 -Wall -Wextra -Wpedantic -Werror
CFLAGS  += -g -O0
CFLAGS  += -D_GNU_SOURCE -D_POSIX_C_SOURCE=200809L

# Include paths. The order matters: public headers first, then
# source tree so that internal headers can be included by their
# path from the repository root (e.g. "core/internal/endian.h").
CFLAGS  += -Iinclude
CFLAGS  += -Isrc
CFLAGS  += -Itests

# Check framework on Linux.
#
# -lsubunit is needed only when Check was built with the
# subunit protocol. It is not present on every system, so it
# is not included by default. If your system has it and the
# link fails without it, add it back to LDLIBS.
LDLIBS  := -lcheck -lm -lpthread -lrt

# ----------------------------------------------------------------------------
# Directories
# ----------------------------------------------------------------------------

BUILD_DIR   := build
OBJ_DIR     := $(BUILD_DIR)/obj
TEST_DIR    := $(BUILD_DIR)/tests
LIB         := $(BUILD_DIR)/libbowie.a

# ----------------------------------------------------------------------------
# Sources
# ----------------------------------------------------------------------------
#
# Library sources. Only files that exist are listed here. When a
# new source file is added to src/, add it to this list.
#
# The list is explicit rather than wildcard so that a file that
# is accidentally added to the tree does not silently enter the
# build.

LIB_SRCS := \
    src/api/version.c \
    src/api/types.c \
    src/api/err.c \
    src/api/config.c \
    src/api/hooks.c \
    src/core/endian.c

# Library objects. The path is rewritten so that the object tree
# mirrors the source tree under build/obj/.

LIB_OBJS := $(LIB_SRCS:src/%.c=$(OBJ_DIR)/%.o)

# ----------------------------------------------------------------------------
# Tests
# ----------------------------------------------------------------------------
#
# Each test is a standalone binary linked against the library.
# A test name is its path under tests/unit/, without the .c
# suffix. The binary is placed under build/tests/ with the same
# path.

UNIT_TEST_SRCS := \
    tests/unit/api/test_version.c \
    tests/unit/api/test_types.c \
    tests/unit/api/test_err.c \
    tests/unit/api/test_config.c \
    tests/unit/api/test_hooks.c \
    tests/unit/core/test_endian.c

UNIT_TEST_BINS := $(UNIT_TEST_SRCS:tests/%.c=$(TEST_DIR)/%)

# ----------------------------------------------------------------------------
# Default target
# ----------------------------------------------------------------------------

.PHONY: all
all: $(LIB)

# ----------------------------------------------------------------------------
# Library
# ----------------------------------------------------------------------------

$(LIB): $(LIB_OBJS)
	@mkdir -p $(dir $@)
	$(AR) rcs $@ $^
	$(RANLIB) $@
	@echo "  AR      $@"

$(OBJ_DIR)/%.o: src/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@
	@echo "  CC      $<"

# ----------------------------------------------------------------------------
# Tests
# ----------------------------------------------------------------------------

.PHONY: test
test: $(UNIT_TEST_BINS)
	@echo
	@echo "═══════════════════════════════════════════"
	@echo " Running Bowie tests"
	@echo "═══════════════════════════════════════════"
	@echo
	@failed=0; \
	total=0; \
	for t in $(UNIT_TEST_BINS); do \
	    total=$$((total + 1)); \
	    echo "── $$t ──"; \
	    if ! $$t; then \
	        failed=$$((failed + 1)); \
	    fi; \
	    echo; \
	done; \
	echo "═══════════════════════════════════════════"; \
	echo " Suites: $$total   Failed: $$failed"; \
	echo "═══════════════════════════════════════════"; \
	exit $$failed

$(TEST_DIR)/%: tests/%.c $(LIB)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $< $(LIB) $(LDLIBS) -o $@
	@echo "  CC      $<"

# ----------------------------------------------------------------------------
# Clean
# ----------------------------------------------------------------------------

.PHONY: clean
clean:
	rm -rf $(BUILD_DIR)
	@echo "  CLEAN   $(BUILD_DIR)"

# ----------------------------------------------------------------------------
# Help
# ----------------------------------------------------------------------------

.PHONY: help
help:
	@echo "Bowie — Makefile targets:"
	@echo
	@echo "  all      build the static library (default)"
	@echo "  test     build and run the unit tests"
	@echo "  clean    remove the build directory"
	@echo "  help     print this help"
	@echo
	@echo "Variables:"
	@echo
	@echo "  CC       C compiler (default: cc)"
	@echo "  V        set V=1 for verbose output"

# ----------------------------------------------------------------------------
# Verbose
# ----------------------------------------------------------------------------
#
# Setting V=1 disables the @ prefix on the compile and link
# lines, so every command is echoed. This is the same convention
# the Linux kernel and many other projects use.

ifeq ($(V),1)
Q :=
else
Q := @
endif
