#!/usr/bin/env bash
set -Eeuo pipefail

# Exercise a real Metered signaling exchange between two local Bowie CLI
# processes. Peer IDs and CLI prompts are exchanged through FIFOs automatically.

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
BUILD_DIR="${BUILD_DIR:-out}"
BUILD_PATH="$BUILD_DIR"
[[ "$BUILD_PATH" = /* ]] || BUILD_PATH="$ROOT_DIR/$BUILD_PATH"
BOWIE_BIN="${BOWIE_BIN:-$BUILD_PATH/bowie-linux}"
METERED_API_KEY="${METERED_API_KEY:-}"
METERED_CHANNEL="${METERED_CHANNEL:-}"
START_TIMEOUT="${START_TIMEOUT:-45}"
CONNECT_TIMEOUT="${CONNECT_TIMEOUT:-140}"
RUN_DIR=""
LISTENER_JOB=""
CONNECTOR_JOB=""
LISTENER_FD=""
CONNECTOR_FD=""

say() { printf '[metered-e2e] %s\n' "$*"; }

cleanup() {
    trap - EXIT INT TERM
    [[ -n "$LISTENER_FD" ]] && { exec {LISTENER_FD}>&- || true; }
    [[ -n "$CONNECTOR_FD" ]] && { exec {CONNECTOR_FD}>&- || true; }
    [[ -n "$LISTENER_JOB" ]] && kill -TERM "$LISTENER_JOB" 2>/dev/null || true
    [[ -n "$CONNECTOR_JOB" ]] && kill -TERM "$CONNECTOR_JOB" 2>/dev/null || true
    [[ -n "$LISTENER_JOB" ]] && wait "$LISTENER_JOB" 2>/dev/null || true
    [[ -n "$CONNECTOR_JOB" ]] && wait "$CONNECTOR_JOB" 2>/dev/null || true
    if [[ -n "$RUN_DIR" ]]; then
        for log in listener connector; do
            if [[ -s "$RUN_DIR/$log.log" ]]; then
                printf '\n--- %s ---\n' "$log" >&2
                tail -n 80 "$RUN_DIR/$log.log" >&2 || true
            fi
        done
        rm -rf -- "$RUN_DIR"
    fi
}

fail() { say "FAIL: $*" >&2; exit 1; }

wait_for_text() {
    local file="$1" needle="$2" timeout="$3" job="$4" attempt=0
    while (( attempt < timeout * 5 )); do
        grep -Fq -- "$needle" "$file" 2>/dev/null && return 0
        kill -0 "$job" 2>/dev/null || return 1
        sleep 0.2
        attempt=$((attempt + 1))
    done
    return 1
}

wait_for_value() {
    local file="$1" name="$2" timeout="$3" job="$4" attempt=0 value
    while (( attempt < timeout * 5 )); do
        value="$(sed -n "s/^${name}=//p" "$file" 2>/dev/null | head -n 1)"
        if [[ -n "$value" ]]; then printf '%s\n' "$value"; return 0; fi
        kill -0 "$job" 2>/dev/null || return 1
        sleep 0.2
        attempt=$((attempt + 1))
    done
    return 1
}

[[ -n "$METERED_API_KEY" ]] || fail 'set METERED_API_KEY to a publishable Metered pk_ key'
[[ -n "$METERED_CHANNEL" ]] || fail 'set METERED_CHANNEL to a channel allowed by the key'
[[ "$START_TIMEOUT" =~ ^[0-9]+$ ]] && (( START_TIMEOUT > 0 )) || fail 'START_TIMEOUT must be positive'
[[ "$CONNECT_TIMEOUT" =~ ^[0-9]+$ ]] && (( CONNECT_TIMEOUT > 0 )) || fail 'CONNECT_TIMEOUT must be positive'

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

say 'Building the Linux CLI with CMake...'
cmake -S "$ROOT_DIR" -B "$BUILD_PATH" || fail 'CMake configure failed'
cmake --build "$BUILD_PATH" --target bowie-linux --parallel || fail 'build failed'
[[ -x "$BOWIE_BIN" ]] || fail "Bowie CLI not found at $BOWIE_BIN"

RUN_DIR="$(mktemp -d /tmp/bowie-metered.XXXXXX)"
mkdir -p "$RUN_DIR/listener-config" "$RUN_DIR/connector-config"
mkfifo "$RUN_DIR/listener.in" "$RUN_DIR/connector.in"
exec {LISTENER_FD}<>"$RUN_DIR/listener.in"
exec {CONNECTOR_FD}<>"$RUN_DIR/connector.in"

say 'Starting Metered listener...'
env XDG_CONFIG_HOME="$RUN_DIR/listener-config" "$BOWIE_BIN" listen - - \
    --signal-metered "$METERED_API_KEY" "$METERED_CHANNEL" \
    <"$RUN_DIR/listener.in" >"$RUN_DIR/listener.log" 2>&1 &
LISTENER_JOB=$!
LISTENER_PEER_ID="$(wait_for_value "$RUN_DIR/listener.log" PEER_ID "$START_TIMEOUT" "$LISTENER_JOB")" ||
    fail 'listener did not print its peer ID'
wait_for_text "$RUN_DIR/listener.log" 'Enter authorized connector peer ID' "$START_TIMEOUT" "$LISTENER_JOB" ||
    fail 'listener did not reach its authorization prompt'

say 'Starting Metered connector and automatically authorizing both peer IDs...'
env XDG_CONFIG_HOME="$RUN_DIR/connector-config" "$BOWIE_BIN" connect - - \
    127.0.0.1 1 "$LISTENER_PEER_ID" \
    --signal-metered "$METERED_API_KEY" "$METERED_CHANNEL" \
    <"$RUN_DIR/connector.in" >"$RUN_DIR/connector.log" 2>&1 &
CONNECTOR_JOB=$!
CONNECTOR_PEER_ID="$(wait_for_value "$RUN_DIR/connector.log" PEER_ID "$START_TIMEOUT" "$CONNECTOR_JOB")" ||
    fail 'connector did not print its peer ID'
wait_for_text "$RUN_DIR/connector.log" 'Verify the expected peer ID' "$START_TIMEOUT" "$CONNECTOR_JOB" ||
    fail 'connector did not reach its confirmation prompt'

printf '%s\n' "$CONNECTOR_PEER_ID" >&"$LISTENER_FD"
printf '\n' >&"$CONNECTOR_FD"

say "Waiting up to ${CONNECT_TIMEOUT}s for the authenticated ICE connection..."
wait_for_text "$RUN_DIR/connector.log" 'CONNECTED' "$CONNECT_TIMEOUT" "$CONNECTOR_JOB" ||
    fail 'connector did not establish the connection'
wait_for_text "$RUN_DIR/listener.log" 'CONNECTED' 15 "$LISTENER_JOB" ||
    fail 'listener did not report the established connection'
say 'PASS: Metered signaling exchanged peer IDs automatically and authenticated the Linux-to-Linux connection.'
