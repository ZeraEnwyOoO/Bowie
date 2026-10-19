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
#   app        build the bowie CLI binary
#   test       build and run the unit tests
#   clean      remove the build directory
#   help       print this help
#
# ----------------------------------------------------------------------------
# Variables
# ----------------------------------------------------------------------------
#
#   CC           C compiler (default: cc)
#   CFLAGS       compiler flags
#   LDFLAGS      linker flags
#   LDLIBS       libraries to link
#   NAT_BACKEND  NAT backend to build (libjuice only in v1)
#   TUNNEL_BACKEND Tunnel backend to build (linux / android)
#   PLATFORM     platform backend (linux / android)
#   V            verbose (V=1 to show full compile commands)
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
# Platform selection
# ----------------------------------------------------------------------------

PLATFORM ?= linux

ifeq ($(PLATFORM),linux)
PLATFORM_DEFS := -DBOWIE_PLATFORM_LINUX
PLATFORM_SRCS := \
    src/platform/posix/init.c \
    src/platform/posix/time.c \
    src/platform/posix/rand.c \
    src/platform/posix/log.c \
    src/platform/posix/sock.c \
    src/platform/linux/netlink.c
else ifeq ($(PLATFORM),android)
PLATFORM_DEFS := -DBOWIE_PLATFORM_ANDROID
PLATFORM_SRCS := \
    src/platform/posix/init.c \
    src/platform/posix/time.c \
    src/platform/posix/rand.c \
    src/platform/posix/log.c \
    src/platform/posix/sock.c \
    src/platform/linux/netlink.c \
    src/platform/android/jni.c \
    src/platform/android/log.c \
    src/platform/android/permissions.c
else
$(error Unknown PLATFORM: $(PLATFORM). Use linux or android.)
endif

# ----------------------------------------------------------------------------
# NAT backend selection
# ----------------------------------------------------------------------------

NAT_BACKEND ?= libjuice

ifeq ($(NAT_BACKEND),libjuice)
NAT_SRCS := src/nat/nat_libjuice.c
NAT_LIBS := -ljuice
else
$(error Unknown NAT_BACKEND: $(NAT_BACKEND). Use libjuice.)
endif

# ----------------------------------------------------------------------------
# Tunnel backend selection
# ----------------------------------------------------------------------------

TUNNEL_BACKEND ?= linux

ifeq ($(TUNNEL_BACKEND),linux)
TUNNEL_SRCS := src/tunnel/tun_linux.c
else ifeq ($(TUNNEL_BACKEND),android)
$(error TUNNEL_BACKEND=android is not implemented yet. Use linux.)
else
$(error Unknown TUNNEL_BACKEND: $(TUNNEL_BACKEND). Use linux.)
endif

# ----------------------------------------------------------------------------
# Flags
# ----------------------------------------------------------------------------

CFLAGS  := -std=c11 -Wall -Wextra -Wpedantic -Werror
CFLAGS  += -g -O0
CFLAGS  += -D_GNU_SOURCE -D_POSIX_C_SOURCE=200809L
CFLAGS  += $(PLATFORM_DEFS)

CFLAGS  += -Iinclude
CFLAGS  += -Isrc
CFLAGS  += -Itests
CFLAGS  += -MMD -MP

# OpenSSL
CFLAGS  += $(shell pkg-config --cflags libcrypto)
LDLIBS  += $(shell pkg-config --libs libcrypto)

# Check framework & NAT dependencies
LDLIBS  += -lcheck -lm -lpthread -lrt
LDLIBS  += $(NAT_LIBS)

# ----------------------------------------------------------------------------
# Directories
# ----------------------------------------------------------------------------

BUILD_DIR   := build
OBJ_DIR     := $(BUILD_DIR)/obj
TEST_DIR    := $(BUILD_DIR)/tests
APP_DIR     := $(BUILD_DIR)/bin
LIB         := $(BUILD_DIR)/libbowie.a
APP         := $(APP_DIR)/bowie

# ----------------------------------------------------------------------------
# Sources
# ----------------------------------------------------------------------------

LIB_SRCS := \
    src/api/version.c \
    src/api/types.c \
    src/api/err.c \
    src/api/config.c \
    src/api/hooks.c \
    src/core/endian.c \
    src/core/mem.c \
    src/core/bytes.c \
    src/core/time.c \
    src/core/rand.c \
    src/core/log.c \
    src/core/sock.c \
    src/crypto/hash.c \
    src/crypto/cipher.c \
    src/crypto/sign.c \
    src/crypto/keypair.c \
    src/net/capabilities.c \
    src/net/peer.c \
    src/dht/types.c \
    src/dht/bencode.c \
    src/dht/message.c \
    src/dht/node.c \
    src/dht/bucket.c \
    src/dht/routing.c \
    src/dht/storage.c \
    src/dht/token.c \
    src/dht/security.c \
    src/dht/search.c \
    src/dht/config.c \
    src/dht/dht.c \
    src/proto/message.c \
    src/proto/framing.c \
    src/proto/handshake.c \
    src/proto/stream.c \
    src/nat/nat.c \
    src/tunnel/mtu.c \
    src/tunnel/packet.c \
    src/security/grant.c \
    src/security/ownership.c \
    src/security/revoke.c \
    src/security/session.c \
    src/security/permission.c \
    src/security/sign.c \
    src/security/keypair.c \
    src/security/kdf.c \
    src/security/quota.c \
    src/gateway/gateway.c \
    src/gateway/ip_forward.c \
    src/gateway/conntrack.c \
    src/gateway/route.c \
    src/engine/state.c \
    src/engine/event.c \
    src/engine/signal.c \
    src/engine/engine.c \
    $(PLATFORM_SRCS) \
    $(NAT_SRCS) \
    $(TUNNEL_SRCS)

LIB_OBJS := $(LIB_SRCS:src/%.c=$(OBJ_DIR)/%.o)

# ----------------------------------------------------------------------------
# Tests
# ----------------------------------------------------------------------------

UNIT_TEST_SRCS := \
    tests/unit/api/test_version.c \
    tests/unit/api/test_types.c \
    tests/unit/api/test_err.c \
    tests/unit/api/test_config.c \
    tests/unit/api/test_hooks.c \
    tests/unit/core/test_endian.c \
    tests/unit/core/test_mem.c \
    tests/unit/core/test_bytes.c \
    tests/unit/core/test_time.c \
    tests/unit/core/test_rand.c \
    tests/unit/core/test_log.c \
    tests/unit/core/test_sock.c \
    tests/unit/crypto/test_hash.c \
    tests/unit/crypto/test_cipher.c \
    tests/unit/crypto/test_sign.c \
    tests/unit/crypto/test_keypair.c \
    tests/unit/net/test_capabilities.c \
    tests/unit/net/test_peer.c \
    tests/unit/dht/test_types.c \
    tests/unit/dht/test_bencode.c \
    tests/unit/dht/test_message.c \
    tests/unit/dht/test_node.c \
    tests/unit/dht/test_bucket.c \
    tests/unit/dht/test_routing.c \
    tests/unit/dht/test_storage.c \
    tests/unit/dht/test_token.c \
    tests/unit/dht/test_security.c \
    tests/unit/dht/test_search.c \
    tests/unit/dht/test_config.c \
    tests/unit/dht/test_dht.c \
    tests/unit/proto/test_message.c \
    tests/unit/proto/test_framing.c \
    tests/unit/proto/test_handshake.c \
    tests/unit/nat/test_nat.c \
    tests/unit/tunnel/test_mtu.c \
    tests/unit/tunnel/test_packet.c \
    tests/unit/tunnel/test_tun_linux.c \
    tests/unit/security/test_grant.c \
    tests/unit/security/test_ownership.c \
    tests/unit/security/test_revoke.c \
    tests/unit/security/test_session.c \
    tests/unit/security/test_permission.c \
    tests/unit/gateway/test_route.c \
    tests/unit/gateway/test_conntrack.c \
    tests/unit/gateway/test_ip_forward.c \
    tests/unit/gateway/test_gateway.c

UNIT_TEST_BINS := $(UNIT_TEST_SRCS:tests/%.c=$(TEST_DIR)/%)

# ----------------------------------------------------------------------------
# Phony targets
# ----------------------------------------------------------------------------

.PHONY: all app test clean help

# ----------------------------------------------------------------------------
# Default target
# ----------------------------------------------------------------------------

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
# App Binary
# ----------------------------------------------------------------------------

app: $(APP)

$(APP): platforms/linux/main.c $(LIB)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $< $(LIB) $(LDLIBS) -o $@
	@echo "  LINK    $@"

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
	@echo "  app      build the bowie CLI binary"
	@echo "  test     build and run the unit tests"
	@echo "  clean    remove the build directory"
	@echo "  help     print this help"
	@echo
	@echo "Variables:"
	@echo
	@echo "  CC             C compiler (default: cc)"
	@echo "  PLATFORM       platform backend (linux / android)"
	@echo "  NAT_BACKEND    NAT backend (libjuice)"
	@echo "  TUNNEL_BACKEND Tunnel backend (linux)"
	@echo "  V              set V=1 for verbose output"
	@echo
	@echo "Examples:"
	@echo
	@echo "  make"
	@echo "  make app"
	@echo "  make test"
	@echo "  make PLATFORM=android"
	@echo "  make NAT_BACKEND=libjuice"
	@echo "  make clean && make test"
	@echo "  make V=1 test"

# ----------------------------------------------------------------------------
# Verbose
# ----------------------------------------------------------------------------

ifeq ($(V),1)
Q :=
else
Q := @
endif

# ----------------------------------------------------------------------------
# Header dependencies
# ----------------------------------------------------------------------------

-include $(LIB_OBJS:.o=.d)
