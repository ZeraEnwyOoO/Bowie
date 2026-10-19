 # ============================================================================
# Bowie — Makefile (Prototype Phase)
# ============================================================================

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
else
$(error Unknown PLATFORM: $(PLATFORM). Use linux.)
endif

# ----------------------------------------------------------------------------
# NAT Backend
# ----------------------------------------------------------------------------
NAT_BACKEND ?= libjuice

ifeq ($(NAT_BACKEND),libjuice)
NAT_SRCS := src/nat/nat_libjuice.c
NAT_LIBS := -ljuice
else
$(error Unknown NAT_BACKEND: $(NAT_BACKEND). Use libjuice.)
endif

# ----------------------------------------------------------------------------
# Tunnel Backend
# ----------------------------------------------------------------------------
TUNNEL_BACKEND ?= linux

ifeq ($(TUNNEL_BACKEND),linux)
TUNNEL_SRCS := src/tunnel/tun_linux.c
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
LDLIBS  += -lcrypto

# Check framework and pthread
LDLIBS  += -lm -lpthread -lrt

# NAT backend libraries
LDLIBS  += $(NAT_LIBS)

# ----------------------------------------------------------------------------
# Directories
# ----------------------------------------------------------------------------
BUILD_DIR   := build
OBJ_DIR     := $(BUILD_DIR)/obj
LIB         := $(BUILD_DIR)/libbowie.a
APP_BIN     := $(BUILD_DIR)/bowie-linux

# ----------------------------------------------------------------------------
# Sources — Library
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
    src/gateway/gateway.c \
    src/gateway/ip_forward.c \
    src/gateway/conntrack.c \
    src/gateway/route.c \
    src/engine/engine.c \
    src/engine/state.c \
    src/engine/event.c \
    src/engine/signal.c \
    $(PLATFORM_SRCS) \
    $(NAT_SRCS) \
    $(TUNNEL_SRCS)

LIB_OBJS := $(LIB_SRCS:src/%.c=$(OBJ_DIR)/%.o)

# ----------------------------------------------------------------------------
# Sources — App
# ----------------------------------------------------------------------------
APP_SRCS := platforms/linux/main.c
APP_OBJS := $(APP_SRCS:platforms/linux/%.c=$(OBJ_DIR)/platforms/linux/%.o)

# ----------------------------------------------------------------------------
# Targets
# ----------------------------------------------------------------------------
.PHONY: all app clean help

all: $(LIB) $(APP_BIN)

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
# App
# ----------------------------------------------------------------------------
$(OBJ_DIR)/platforms/linux/%.o: platforms/linux/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@
	@echo "  CC      $<"

$(APP_BIN): $(APP_OBJS) $(LIB)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(APP_OBJS) $(LIB) $(LDLIBS) -o $@
	@echo "  LD      $@"

app: $(APP_BIN)

# ----------------------------------------------------------------------------
# Clean
# ----------------------------------------------------------------------------
clean:
	rm -rf $(BUILD_DIR)
	@echo "  CLEAN   $(BUILD_DIR)"

# ----------------------------------------------------------------------------
# Help
# ----------------------------------------------------------------------------
help:
	@echo "Bowie — Makefile targets:"
	@echo
	@echo "  all      build the static library and the linux executable (default)"
	@echo "  app      build only the linux executable"
	@echo "  clean    remove the build directory"
	@echo "  help     print this help"

# ----------------------------------------------------------------------------
# Header dependencies
# ----------------------------------------------------------------------------
-include $(LIB_OBJS:.o=.d)
-include $(APP_OBJS:.o=.d)
