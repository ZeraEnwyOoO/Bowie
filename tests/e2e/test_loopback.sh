#!/usr/bin/env bash
set -Eeuo pipefail

# Run a complete two-peer Linux tunnel test on one host. Network namespaces
# keep the two overlay routes separate, so the ping cannot accidentally hit a
# locally assigned overlay address.

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
BUILD_DIR="${BUILD_DIR:-out}"
BUILD_PATH="$BUILD_DIR"
[[ "$BUILD_PATH" = /* ]] || BUILD_PATH="$ROOT_DIR/$BUILD_PATH"
BOWIE_BIN="${BOWIE_BIN:-$BUILD_PATH/bowie-linux}"
RELAY_BIN="${RELAY_BIN:-$BUILD_PATH/bowie-signal-relay}"
RELAY_PORT="${RELAY_PORT:-3479}"
START_TIMEOUT="${START_TIMEOUT:-30}"
CONNECT_TIMEOUT="${CONNECT_TIMEOUT:-140}"
LOSS_PERCENT="${LOSS_PERCENT:-0}"
PING_COUNT="${PING_COUNT:-5}"
PING_SIZE="${PING_SIZE:-56}"

RUN_DIR=""
RELAY_PID=""
LISTENER_JOB=""
CONNECTOR_JOB=""
LISTENER_CAPTURE_JOB=""
CONNECTOR_CAPTURE_JOB=""
LISTENER_CAPTURE_PIDFILE=""
CONNECTOR_CAPTURE_PIDFILE=""
LISTENER_NS=""
CONNECTOR_NS=""
BRIDGE=""
LISTENER_INPUT_FD=""
CONNECTOR_INPUT_FD=""

say() { printf '[loopback] %s\n' "$*"; }

show_netem_counters() {
    (( LOSS_PERCENT > 0 )) || return 0
    say "Listener link loss counters:"
    run_root ip netns exec "$LISTENER_NS" tc -s qdisc show dev "vln$$" || true
    say "Connector link loss counters:"
    run_root ip netns exec "$CONNECTOR_NS" tc -s qdisc show dev "vcn$$" || true
}

show_route_diagnostics() {
    [[ -n "$LISTENER_NS" ]] || return 0
    say "Listener namespace routes:"
    run_root ip netns exec "$LISTENER_NS" ip -4 route show 2>&1 || true
    run_root ip netns exec "$LISTENER_NS" ip -4 route get 192.0.2.3 2>&1 || true
    say "Connector namespace routes:"
    run_root ip netns exec "$CONNECTOR_NS" ip -4 route show 2>&1 || true
    run_root ip netns exec "$CONNECTOR_NS" ip -4 route get 192.0.2.2 2>&1 || true
}

stop_captures() {
    local pidfile pid
    for pidfile in "$LISTENER_CAPTURE_PIDFILE" "$CONNECTOR_CAPTURE_PIDFILE"; do
        [[ -n "$pidfile" && -s "$pidfile" ]] || continue
        pid="$(cat "$pidfile" 2>/dev/null || true)"
        [[ "$pid" =~ ^[0-9]+$ ]] && run_root kill -INT "$pid" 2>/dev/null || true
    done
    [[ -n "$LISTENER_CAPTURE_JOB" ]] && wait "$LISTENER_CAPTURE_JOB" 2>/dev/null || true
    [[ -n "$CONNECTOR_CAPTURE_JOB" ]] && wait "$CONNECTOR_CAPTURE_JOB" 2>/dev/null || true
    LISTENER_CAPTURE_JOB=""
    CONNECTOR_CAPTURE_JOB=""
}

show_capture() {
    local file="$1"
    [[ -s "$file" ]] || return 0
    printf '\n--- %s ---\n' "${file##*/}" >&2
    tail -n 100 "$file" >&2 || true
    printf '%s\n' '--- end capture ---' >&2
}

run_root() {
    if (( EUID == 0 )); then
        "$@"
    else
        sudo -n "$@"
    fi
}

show_log_tail() {
    local file="$1"
    if [[ -s "$file" ]]; then
        printf '\n--- %s ---\n' "${file##*/}" >&2
        if grep -Eq 'ICE_SELECTED_ADDRESS|NAT_(DATA_DATAGRAM_RECEIVED|FRAGMENT_)|GATEWAY_PACKET_(FORWARDED|DROPPED)' "$file"; then
            grep -E 'ICE_SELECTED_ADDRESS|NAT_(DATA_DATAGRAM_RECEIVED|FRAGMENT_)|GATEWAY_PACKET_(FORWARDED|DROPPED)' "$file" | tail -n 80 >&2 || true
        else
            tail -n 40 "$file" >&2 || true
        fi
        printf '%s\n' '--- end log ---' >&2
    fi
}

cleanup() {
    local ns pid
    trap - EXIT INT TERM

    stop_captures

    [[ -n "$LISTENER_INPUT_FD" ]] && { exec {LISTENER_INPUT_FD}>&- || true; }
    [[ -n "$CONNECTOR_INPUT_FD" ]] && { exec {CONNECTOR_INPUT_FD}>&- || true; }

    for ns in "$LISTENER_NS" "$CONNECTOR_NS"; do
        [[ -n "$ns" ]] || continue
        local pids
        pids="$(run_root ip netns pids "$ns" 2>/dev/null || true)"
        for pid in $pids; do
            run_root kill -TERM "$pid" 2>/dev/null || true
        done
    done

    if [[ -n "$RELAY_PID" ]]; then
        kill -TERM "$RELAY_PID" 2>/dev/null || true
        wait "$RELAY_PID" 2>/dev/null || true
    fi
    [[ -n "$LISTENER_JOB" ]] && wait "$LISTENER_JOB" 2>/dev/null || true
    [[ -n "$CONNECTOR_JOB" ]] && wait "$CONNECTOR_JOB" 2>/dev/null || true

    for ns in "$LISTENER_NS" "$CONNECTOR_NS"; do
        [[ -n "$ns" ]] || continue
        run_root ip netns del "$ns" 2>/dev/null || true
    done
    [[ -n "$BRIDGE" ]] && run_root ip link del "$BRIDGE" 2>/dev/null || true
    [[ -n "$RUN_DIR" ]] && rm -rf -- "$RUN_DIR"
}

fail() {
    say "FAIL: $*" >&2
    [[ -n "$RUN_DIR" ]] && {
        show_route_diagnostics
        show_log_tail "$RUN_DIR/relay.log"
        show_log_tail "$RUN_DIR/listener.log"
        show_log_tail "$RUN_DIR/connector.log"
        show_capture "$RUN_DIR/listener-udp.txt"
        show_capture "$RUN_DIR/connector-udp.txt"
    }
    exit 1
}

wait_for_text() {
    local file="$1" text="$2" timeout="$3" job="$4" attempt=0
    while (( attempt < timeout * 5 )); do
        grep -Fq -- "$text" "$file" 2>/dev/null && return 0
        if [[ -n "$job" ]] && ! kill -0 "$job" 2>/dev/null; then
            return 1
        fi
        sleep 0.2
        attempt=$((attempt + 1))
    done
    return 1
}

wait_for_value() {
    local file="$1" prefix="$2" timeout="$3" job="$4" attempt=0 value
    while (( attempt < timeout * 5 )); do
        value="$(sed -n "s/^${prefix}=//p" "$file" 2>/dev/null | head -n 1)"
        if [[ -n "$value" ]]; then
            printf '%s\n' "$value"
            return 0
        fi
        if [[ -n "$job" ]] && ! kill -0 "$job" 2>/dev/null; then
            return 1
        fi
        sleep 0.2
        attempt=$((attempt + 1))
    done
    return 1
}

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

for tool in ip ping mkfifo tcpdump; do
    command -v "$tool" >/dev/null 2>&1 || fail "required command '$tool' was not found"
done
if (( EUID != 0 )); then
    command -v sudo >/dev/null 2>&1 || fail "sudo is required to create TUN devices and network namespaces"
    sudo -v || fail "could not obtain sudo credentials"
fi

say "Building the Linux CLI and signaling relay with CMake..."
cmake -S "$ROOT_DIR" -B "$BUILD_PATH" || fail "CMake configure failed"
cmake --build "$BUILD_PATH" --target bowie-linux bowie-signal-relay --parallel || fail "build failed"
[[ -x "$BOWIE_BIN" ]] || fail "Bowie CLI not found at $BOWIE_BIN"
[[ -x "$RELAY_BIN" ]] || fail "signaling relay not found at $RELAY_BIN"

[[ "$RELAY_PORT" =~ ^[0-9]+$ ]] && (( RELAY_PORT >= 1 && RELAY_PORT <= 65535 )) || fail "RELAY_PORT must be between 1 and 65535"
[[ "$START_TIMEOUT" =~ ^[0-9]+$ ]] && (( START_TIMEOUT > 0 )) || fail "START_TIMEOUT must be a positive number of seconds"
[[ "$CONNECT_TIMEOUT" =~ ^[0-9]+$ ]] && (( CONNECT_TIMEOUT > 0 )) || fail "CONNECT_TIMEOUT must be a positive number of seconds"
[[ "$LOSS_PERCENT" =~ ^[0-9]+$ ]] && (( LOSS_PERCENT <= 99 )) || fail "LOSS_PERCENT must be between 0 and 99"
[[ "$PING_COUNT" =~ ^[0-9]+$ ]] && (( PING_COUNT > 0 )) || fail "PING_COUNT must be a positive number of packets"
[[ "$PING_SIZE" =~ ^[0-9]+$ ]] && (( PING_SIZE <= 1472 )) || fail "PING_SIZE must be between 0 and 1472 bytes for the 1500-byte tunnel MTU"
if (( LOSS_PERCENT > 0 )); then
    command -v tc >/dev/null 2>&1 || fail "tc is required when LOSS_PERCENT is nonzero"
fi

RUN_DIR="$(mktemp -d /tmp/bowie-loopback.XXXXXX)"
mkdir -p /tmp/bowie-listener /tmp/bowie-connector
LISTENER_NS="bwl$$"
CONNECTOR_NS="bwc$$"
BRIDGE="bwb$$"

say "Creating isolated listener and connector network namespaces..."
run_root ip netns add "$LISTENER_NS" || fail "could not create listener namespace"
run_root ip netns add "$CONNECTOR_NS" || fail "could not create connector namespace"
run_root ip link add "$BRIDGE" type bridge || fail "could not create bridge"
run_root ip addr add 192.0.2.1/24 dev "$BRIDGE" || fail "could not configure test bridge"
run_root ip link set "$BRIDGE" up || fail "could not bring test bridge up"

run_root ip link add "vll$$" type veth peer name "vln$$" || fail "could not create listener veth"
run_root ip link set "vln$$" netns "$LISTENER_NS" || fail "could not move listener veth"
run_root ip link set "vll$$" master "$BRIDGE"
run_root ip link set "vll$$" up
run_root ip netns exec "$LISTENER_NS" ip link set lo up
run_root ip netns exec "$LISTENER_NS" ip addr add 192.0.2.2/24 dev "vln$$"
run_root ip netns exec "$LISTENER_NS" ip link set "vln$$" up

run_root ip link add "vcl$$" type veth peer name "vcn$$" || fail "could not create connector veth"
run_root ip link set "vcn$$" netns "$CONNECTOR_NS" || fail "could not move connector veth"
run_root ip link set "vcl$$" master "$BRIDGE"
run_root ip link set "vcl$$" up
run_root ip netns exec "$CONNECTOR_NS" ip link set lo up
run_root ip netns exec "$CONNECTOR_NS" ip addr add 192.0.2.3/24 dev "vcn$$"
run_root ip netns exec "$CONNECTOR_NS" ip link set "vcn$$" up

say "Checking direct peer routes across the test bridge..."
LISTENER_ROUTE="$(run_root ip netns exec "$LISTENER_NS" ip -4 route get 192.0.2.3)" || fail "listener cannot route to connector veth"
CONNECTOR_ROUTE="$(run_root ip netns exec "$CONNECTOR_NS" ip -4 route get 192.0.2.2)" || fail "connector cannot route to listener veth"
[[ "$LISTENER_ROUTE" == *"dev vln$$"* ]] || fail "listener route to 192.0.2.3 does not use vln$$: $LISTENER_ROUTE"
[[ "$CONNECTOR_ROUTE" == *"dev vcn$$"* ]] || fail "connector route to 192.0.2.2 does not use vcn$$: $CONNECTOR_ROUTE"
say "Listener route: $LISTENER_ROUTE"
say "Connector route: $CONNECTOR_ROUTE"

mkfifo "$RUN_DIR/listener.in" "$RUN_DIR/connector.in"
exec {LISTENER_INPUT_FD}<>"$RUN_DIR/listener.in"
exec {CONNECTOR_INPUT_FD}<>"$RUN_DIR/connector.in"

say "Starting UDP signal relay on 0.0.0.0:$RELAY_PORT..."
run_root ip netns exec "$LISTENER_NS" \
    "$RELAY_BIN" 0.0.0.0 "$RELAY_PORT" >"$RUN_DIR/relay.log" 2>&1 &
RELAY_PID=$!
wait_for_text "$RUN_DIR/relay.log" 'RELAY_STARTED' 5 "$RELAY_PID" || fail "signal relay did not start (port $RELAY_PORT may be in use)"

say "Starting listener..."
run_root ip netns exec "$LISTENER_NS" env XDG_CONFIG_HOME=/tmp/bowie-listener \
    "$BOWIE_BIN" listen bowie0 10.77.0.1/24 \
    --signal-relay 192.0.2.2 "$RELAY_PORT" \
    --ice-bind 192.0.2.2 \
    <"$RUN_DIR/listener.in" >"$RUN_DIR/listener.log" 2>&1 &
LISTENER_JOB=$!

LISTENER_PEER_ID="$(wait_for_value "$RUN_DIR/listener.log" PEER_ID "$START_TIMEOUT" "$LISTENER_JOB")" || fail "listener did not print its peer ID"
LISTENER_SIGNAL_PORT="$(wait_for_value "$RUN_DIR/listener.log" SIGNAL_PORT "$START_TIMEOUT" "$LISTENER_JOB")" || fail "listener did not print its signal port"
LISTENER_MTU="$(run_root ip netns exec "$LISTENER_NS" ip -o link show bowie0 | sed -n 's/.* mtu \([0-9][0-9]*\) .*/\1/p')"
[[ "$LISTENER_MTU" == 1500 ]] || fail "listener TUN MTU is ${LISTENER_MTU:-unknown}, expected 1500"
wait_for_text "$RUN_DIR/listener.log" 'Enter authorized connector peer ID' "$START_TIMEOUT" "$LISTENER_JOB" || fail "listener did not reach its peer authorization prompt"
say "Listener peer ID: $LISTENER_PEER_ID (signal port $LISTENER_SIGNAL_PORT)"
wait_for_text "$RUN_DIR/relay.log" "\"peer\":\"$LISTENER_PEER_ID\"" "$START_TIMEOUT" "$RELAY_PID" || fail "listener did not register with the signal relay"

CONNECTOR_PEER_ID="$(run_root ip netns exec "$CONNECTOR_NS" env XDG_CONFIG_HOME=/tmp/bowie-connector \
    "$BOWIE_BIN" identity)" || fail "could not read connector identity"
run_root env XDG_CONFIG_HOME=/tmp/bowie-listener \
    "$BOWIE_BIN" grant "$CONNECTOR_PEER_ID" "$RUN_DIR/connector.grant" >/dev/null ||
    fail "listener could not issue connector grant"

say "Starting connector..."
run_root ip netns exec "$CONNECTOR_NS" env XDG_CONFIG_HOME=/tmp/bowie-connector \
    "$BOWIE_BIN" connect bowie1 10.77.0.2/24 192.0.2.2 "$LISTENER_SIGNAL_PORT" "$LISTENER_PEER_ID" \
    --grant-file "$RUN_DIR/connector.grant" \
    --signal-relay 192.0.2.2 "$RELAY_PORT" \
    --ice-bind 192.0.2.3 \
    <"$RUN_DIR/connector.in" >"$RUN_DIR/connector.log" 2>&1 &
CONNECTOR_JOB=$!

CONNECTOR_PEER_ID_FROM_CONNECT="$(wait_for_value "$RUN_DIR/connector.log" PEER_ID "$START_TIMEOUT" "$CONNECTOR_JOB")" || fail "connector did not print its peer ID"
[[ "$CONNECTOR_PEER_ID_FROM_CONNECT" == "$CONNECTOR_PEER_ID" ]] || fail "connector identity changed between grant and connect"
CONNECTOR_MTU="$(run_root ip netns exec "$CONNECTOR_NS" ip -o link show bowie1 | sed -n 's/.* mtu \([0-9][0-9]*\) .*/\1/p')"
[[ "$CONNECTOR_MTU" == 1500 ]] || fail "connector TUN MTU is ${CONNECTOR_MTU:-unknown}, expected 1500"
wait_for_text "$RUN_DIR/connector.log" 'Verify the expected peer ID' "$START_TIMEOUT" "$CONNECTOR_JOB" || fail "connector did not reach its confirmation prompt"
say "Connector peer ID: $CONNECTOR_PEER_ID"
wait_for_text "$RUN_DIR/relay.log" "\"peer\":\"$CONNECTOR_PEER_ID\"" "$START_TIMEOUT" "$RELAY_PID" || fail "connector did not register with the signal relay"

printf '%s\n' "$CONNECTOR_PEER_ID" >&"$LISTENER_INPUT_FD"
printf '\n' >&"$CONNECTOR_INPUT_FD"

say "Waiting for authenticated tunnel connection..."
if ! wait_for_text "$RUN_DIR/relay.log" 'SIGNAL_FORWARDED' 10 "$RELAY_PID"; then
    fail "signal relay did not forward the connector offer"
fi
if ! wait_for_text "$RUN_DIR/connector.log" 'CONNECTED.' "$CONNECT_TIMEOUT" "$CONNECTOR_JOB"; then
    fail "connector did not connect within ${CONNECT_TIMEOUT}s"
fi
if ! wait_for_text "$RUN_DIR/listener.log" 'CONNECTED.' 10 "$LISTENER_JOB"; then
    fail "listener did not report the established connection"
fi

if (( LOSS_PERCENT > 0 )); then
    say "Applying ${LOSS_PERCENT}% network loss to both peer links..."
    run_root ip netns exec "$LISTENER_NS" tc qdisc replace dev "vln$$" root netem loss "${LOSS_PERCENT}%"
    run_root ip netns exec "$CONNECTOR_NS" tc qdisc replace dev "vcn$$" root netem loss "${LOSS_PERCENT}%"
fi

say "Capturing UDP on both peer namespaces while ping runs..."
LISTENER_CAPTURE_PIDFILE="$RUN_DIR/listener-tcpdump.pid"
CONNECTOR_CAPTURE_PIDFILE="$RUN_DIR/connector-tcpdump.pid"
run_root ip netns exec "$LISTENER_NS" sh -c 'echo $$ > "$1"; exec tcpdump -l -n -tttt -i "$2" udp' sh "$LISTENER_CAPTURE_PIDFILE" "vln$$" >"$RUN_DIR/listener-udp.txt" 2>&1 &
LISTENER_CAPTURE_JOB=$!
run_root ip netns exec "$CONNECTOR_NS" sh -c 'echo $$ > "$1"; exec tcpdump -l -n -tttt -i "$2" udp' sh "$CONNECTOR_CAPTURE_PIDFILE" "vcn$$" >"$RUN_DIR/connector-udp.txt" 2>&1 &
CONNECTOR_CAPTURE_JOB=$!
sleep 0.2
[[ -s "$LISTENER_CAPTURE_PIDFILE" && -s "$CONNECTOR_CAPTURE_PIDFILE" ]] || fail "tcpdump did not start in both namespaces"

say "Pinging connector overlay address 10.77.0.2 from the listener namespace ($PING_COUNT packets, $PING_SIZE-byte payload)..."
if run_root ip netns exec "$LISTENER_NS" ping -M do -s "$PING_SIZE" -c "$PING_COUNT" -i 0.1 -W 2 10.77.0.2 | tee "$RUN_DIR/ping.log"; then
    stop_captures
    show_netem_counters
    PING_RECEIVED="$(sed -nE 's/^[0-9]+ packets transmitted, ([0-9]+) received,.*/\1/p' "$RUN_DIR/ping.log" | tail -n 1)"
    [[ "$PING_RECEIVED" =~ ^[0-9]+$ ]] || fail "could not parse ping reply count"
    say "Ping replies: $PING_RECEIVED/$PING_COUNT"
    if (( LOSS_PERCENT == 0 && PING_RECEIVED != PING_COUNT )); then
        fail "no-loss baseline was incomplete: received $PING_RECEIVED of $PING_COUNT replies"
    fi
    if (( LOSS_PERCENT > 0 )); then
        say "PASS: overlay ping returned replies with configured ${LOSS_PERCENT}% link loss"
    else
        say "PASS: authenticated peer connection and overlay ping succeeded"
    fi
    exit 0
else
    stop_captures
    show_netem_counters
    fail "overlay ping to 10.77.0.2 failed"
fi
