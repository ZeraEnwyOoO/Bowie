#!/usr/bin/env bash
set -Eeuo pipefail

# Build/install the debug app, then verify an overlay ping through a Linux TUN.
# IDs and signal ports are exchanged by this script.
ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
SDK_ROOT="${ANDROID_SDK_ROOT:-${ANDROID_HOME:-$HOME/android-sdk}}"
ADB="${ADB:-$(command -v adb || printf '%s/platform-tools/adb' "$SDK_ROOT")}"
BUILD_DIR="${BUILD_DIR:-out}"
BUILD_PATH="$BUILD_DIR"
[[ "$BUILD_PATH" = /* ]] || BUILD_PATH="$ROOT_DIR/$BUILD_PATH"
BOWIE_BIN="${BOWIE_BIN:-$BUILD_PATH/bowie-linux}"
BOWIE_RELAY_BIN="${BOWIE_RELAY_BIN:-$BUILD_PATH/bowie-signal-relay}"
BOWIE_ANDROID_DEPS="${BOWIE_ANDROID_DEPS:-$ROOT_DIR/../bowie_deps}"
ANDROID_ABI="${ANDROID_ABI:-arm64-v8a}"
RELAY_PORT="${RELAY_PORT:-3479}"
METERED_API_KEY="${METERED_API_KEY:-}"
METERED_CHANNEL="${METERED_CHANNEL:-}"
STUN_HOST="${BOWIE_STUN_HOST:-}"
STUN_PORT="${BOWIE_STUN_PORT:-3478}"
STUN_PORT_OVERRIDE="${BOWIE_STUN_PORT:-}"
TURN_HOST="${BOWIE_TURN_HOST:-}"
TURN_PORT="${BOWIE_TURN_PORT:-}"
TURN_USERNAME="${BOWIE_TURN_USERNAME:-}"
TURN_PASSWORD="${BOWIE_TURN_PASSWORD:-}"
TURN_ENV_FILE="${BOWIE_TURN_ENV_FILE:-$HOME/.config/bowie/turn.env}"
LINUX_RELAY_HOST="${BOWIE_LINUX_RELAY_HOST:-}"
PHONE_RELAY_HOST="${BOWIE_PHONE_RELAY_HOST:-}"
START_TIMEOUT="${START_TIMEOUT:-45}"
CONNECT_TIMEOUT="${CONNECT_TIMEOUT:-45}"
PHONE_OVERLAY="${PHONE_OVERLAY:-10.77.0.2}"
LINUX_OVERLAY="${LINUX_OVERLAY:-10.77.0.1}"
PING_TARGET="${E2E_PING_TARGET:-$LINUX_OVERLAY}"
OPEN_URL="${E2E_OPEN_URL:-}"
OPEN_SECONDS="${E2E_OPEN_SECONDS:-20}"
HOLD_SECONDS="${E2E_HOLD_SECONDS:-0}"
TUN_NAME="${TUN_NAME:-bwe2e$$}"
RUN_DIR=""
LISTENER_PID=""
RELAY_PID=""
LOGCAT_PID=""
FIFO=""
FIFO_FD=""
USING_EXISTING_RELAY=0
USE_METERED=0
WIFI_WAS_ENABLED=""
WIFI_DISABLED_BY_TEST=0
SUDO=()

say() { printf '[android-linux] %s\n' "$*"; }
fail() { say "FAIL: $*" >&2; exit 1; }

if [[ -n "$OPEN_URL" ]]; then
    [[ "$OPEN_URL" == https://* ]] || fail "E2E_OPEN_URL must use HTTPS"
    [[ "$OPEN_SECONDS" =~ ^[0-9]+$ ]] && (( OPEN_SECONDS >= 1 && OPEN_SECONDS <= 120 )) ||
        fail "E2E_OPEN_SECONDS must be 1..120"
fi
[[ "$HOLD_SECONDS" =~ ^[0-9]+$ ]] && (( HOLD_SECONDS <= 600 )) ||
    fail "E2E_HOLD_SECONDS must be 0..600"

cleanup() {
    local pid
    trap - EXIT INT TERM
    if (( WIFI_DISABLED_BY_TEST == 1 )); then
        "$ADB" shell svc wifi enable >/dev/null 2>&1 || true
        WIFI_DISABLED_BY_TEST=0
    fi
    if [[ -n "$LOGCAT_PID" ]]; then
        kill "$LOGCAT_PID" 2>/dev/null || true
        wait "$LOGCAT_PID" 2>/dev/null || true
    fi
    if [[ -n "$LISTENER_PID" ]]; then
        if [[ -n "$FIFO_FD" ]]; then
            printf '\n' >&"$FIFO_FD" 2>/dev/null || true
        fi
        "${SUDO[@]}" pkill -TERM -P "$LISTENER_PID" 2>/dev/null || true
        "${SUDO[@]}" kill -TERM "$LISTENER_PID" 2>/dev/null || true
        wait "$LISTENER_PID" 2>/dev/null || true
    fi
    if [[ -n "$RELAY_PID" ]]; then
        kill -TERM "$RELAY_PID" 2>/dev/null || true
        wait "$RELAY_PID" 2>/dev/null || true
    fi
    if [[ -n "$FIFO_FD" ]]; then
        exec {FIFO_FD}>&- 2>/dev/null || true
    fi
    "$ADB" shell am force-stop org.bowie >/dev/null 2>&1 || true
    [[ -n "$FIFO" ]] && rm -f -- "$FIFO"
    [[ -n "$RUN_DIR" ]] && say "Logs: $RUN_DIR"
}

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

for tool in cmake gradle python3 ip rg ping; do
    command -v "$tool" >/dev/null 2>&1 || fail "required command '$tool' was not found"
done
if (( EUID != 0 )); then
    command -v sudo >/dev/null 2>&1 || fail "sudo is required to create the Linux TUN interface"
    sudo -n true 2>/dev/null || fail "Linux TUN testing needs sudo; run 'sudo -v' and rerun"
    SUDO=(sudo -n)
fi
[[ -x "$ADB" ]] || fail "ADB not found at $ADB"
[[ -d "$BOWIE_ANDROID_DEPS/include/openssl" && -d "$BOWIE_ANDROID_DEPS/include/juice" ]] ||
    fail "Android dependencies are missing at $BOWIE_ANDROID_DEPS"
"$ADB" wait-for-device
[[ "$("$ADB" get-state)" == device ]] || fail "Android device is not connected"

PHONE_IP="$("$ADB" shell ip -o -4 addr show wlan0 | tr -d '\r' | awk '{for (i=1;i<=NF;i++) if ($i=="inet") {split($(i+1),a,"/"); print a[1]; exit}}')"
if [[ -n "$METERED_API_KEY" || -n "$METERED_CHANNEL" ]]; then
    [[ -n "$METERED_API_KEY" && -n "$METERED_CHANNEL" ]] || fail "set both METERED_API_KEY and METERED_CHANNEL"
    USE_METERED=1
fi
if [[ -f "$TURN_ENV_FILE" ]]; then
    turn_mode="$(stat -c '%a' "$TURN_ENV_FILE")"
    [[ "$(stat -c '%u' "$TURN_ENV_FILE")" == "$EUID" ]] || fail "TURN env file must be owned by the current user"
    (( (8#$turn_mode & 077) == 0 )) || fail "TURN env file must not be readable by group or others"
    while IFS= read -r turn_line || [[ -n "$turn_line" ]]; do
        [[ -z "$turn_line" || "$turn_line" == \#* ]] && continue
        [[ "$turn_line" == *=* ]] || fail "invalid line in TURN env file"
        turn_name="${turn_line%%=*}"
        turn_value="${turn_line#*=}"
        case "$turn_name" in
            BOWIE_STUN_HOST) [[ -n "$STUN_HOST" ]] || STUN_HOST="$turn_value" ;;
            BOWIE_STUN_PORT) [[ -n "$STUN_PORT_OVERRIDE" ]] || STUN_PORT="$turn_value" ;;
            BOWIE_TURN_HOST) [[ -n "$TURN_HOST" ]] || TURN_HOST="$turn_value" ;;
            BOWIE_TURN_PORT) [[ -n "$TURN_PORT" ]] || TURN_PORT="$turn_value" ;;
            BOWIE_TURN_USERNAME) [[ -n "$TURN_USERNAME" ]] || TURN_USERNAME="$turn_value" ;;
            BOWIE_TURN_PASSWORD) [[ -n "$TURN_PASSWORD" ]] || TURN_PASSWORD="$turn_value" ;;
            *) fail "unsupported setting name in TURN env file" ;;
        esac
    done < "$TURN_ENV_FILE"
fi
if [[ -n "$STUN_HOST" ]]; then
    [[ "$STUN_PORT" =~ ^[0-9]+$ ]] && (( STUN_PORT > 0 && STUN_PORT <= 65535 )) || fail "BOWIE_STUN_PORT must be 1..65535"
fi
TURN_ARGS=()
ANDROID_TURN_ARGS=()
if [[ -n "$TURN_HOST$TURN_PORT$TURN_USERNAME$TURN_PASSWORD" ]]; then
    [[ -n "$TURN_HOST" && -n "$TURN_PORT" && -n "$TURN_USERNAME" && -n "$TURN_PASSWORD" ]] ||
        fail "configure TURN host, port, username, and password together"
    [[ "$TURN_PORT" =~ ^[0-9]+$ ]] && (( TURN_PORT > 0 && TURN_PORT <= 65535 )) || fail "TURN port must be 1..65535"
    TURN_ARGS=(--turn "$TURN_HOST" "$TURN_PORT")
    ANDROID_TURN_ARGS=(--es turn_host "$TURN_HOST" --ei turn_port "$TURN_PORT" --es turn_username "$TURN_USERNAME" --es turn_password "$TURN_PASSWORD")
    say "TURN is configured for this single end-to-end attempt."
fi
if [[ "${BOWIE_PHONE_USE_CELLULAR:-0}" == 1 ]]; then
    WIFI_WAS_ENABLED="$("$ADB" shell settings get global wifi_on | tr -d '\r')"
    if [[ "$WIFI_WAS_ENABLED" == 1 ]]; then
        say "Temporarily disabling phone WiFi for the mobile-data test; cleanup will restore it."
        "$ADB" shell svc wifi disable || fail "could not disable phone WiFi"
        WIFI_DISABLED_BY_TEST=1
        sleep 3
    fi
fi
[[ -n "$PHONE_IP" || -n "${BOWIE_ANDROID_HOST:-}" || "$USE_METERED" == 1 ]] || fail "the phone has no IPv4 address on wlan0; connect it to the same Wi-Fi as Linux or set BOWIE_ANDROID_HOST"
ANDROID_HOST="${BOWIE_ANDROID_HOST:-}"
if [[ -z "$ANDROID_HOST" && "$USE_METERED" == 1 ]]; then
    ANDROID_HOST="127.0.0.1"
elif [[ -z "$ANDROID_HOST" ]]; then
    ANDROID_HOST="$(python3 - "$PHONE_IP" <<'PY'
import ipaddress
import subprocess
import sys

phone = ipaddress.ip_address(sys.argv[1])
text = subprocess.check_output(
    ["ip", "-o", "-4", "addr", "show", "scope", "global"], text=True
)
for line in text.splitlines():
    fields = line.split()
    for field in fields:
        if "/" not in field:
            continue
        try:
            iface = ipaddress.ip_interface(field)
        except ValueError:
            continue
        if phone in iface.network and iface.ip != phone:
            print(iface.ip)
            raise SystemExit(0)
raise SystemExit("no Linux interface shares the phone's Wi-Fi subnet")
PY
    )" || fail "could not find a Linux address on the phone's Wi-Fi subnet; set BOWIE_ANDROID_HOST"
fi
LINUX_RELAY_HOST="${LINUX_RELAY_HOST:-$ANDROID_HOST}"
PHONE_RELAY_HOST="${PHONE_RELAY_HOST:-$ANDROID_HOST}"
PHONE_RELAY_PORT="$RELAY_PORT"

RUN_DIR="$(mktemp -d /tmp/bowie-android-linux.XXXXXX)"
FIFO="$RUN_DIR/linux-listener.in"
mkfifo "$FIFO"
exec {FIFO_FD}<>"$FIFO"

say "Running the Linux userspace gateway test, then building the Android peer..."
if ! cmake -S "$ROOT_DIR" -B "$BUILD_PATH" >"$RUN_DIR/linux-local-test.log" 2>&1 ||
   ! cmake --build "$BUILD_PATH" --target e2e-local --parallel >>"$RUN_DIR/linux-local-test.log" 2>&1; then
    cat "$RUN_DIR/linux-local-test.log" >&2
    fail "Linux userspace gateway test failed"
fi
say "Linux userspace gateway test passed."
cmake --build "$BUILD_PATH" --target bowie-linux bowie-signal-relay --parallel || fail "Linux build failed"
gradle -p "$ROOT_DIR/platforms/android" :app:assembleFullDebug \
    -PbowieDeps="$BOWIE_ANDROID_DEPS" -PbowieAbis="$ANDROID_ABI" || fail "Android build failed"
[[ -x "$BOWIE_BIN" ]] || fail "Linux CLI not found at $BOWIE_BIN"
[[ -x "$BOWIE_RELAY_BIN" ]] || fail "signaling relay not found at $BOWIE_RELAY_BIN"

say "Installing updated app on the connected phone..."
"$ADB" install -r "$ROOT_DIR/platforms/android/app/build/outputs/apk/full/debug/app-full-debug.apk" ||
    fail "APK installation failed"
"$ADB" shell am force-stop org.bowie >/dev/null

SIGNAL_ARGS=()
ICE_ARGS=()
ANDROID_RELAY_ARGS=()
ANDROID_ICE_ARGS=()
if [[ -n "$STUN_HOST" ]]; then
    [[ "$STUN_PORT" =~ ^[0-9]+$ ]] && (( STUN_PORT > 0 && STUN_PORT <= 65535 )) || fail "BOWIE_STUN_PORT must be 1..65535"
    ICE_ARGS+=(--stun "$STUN_HOST" "$STUN_PORT")
    ANDROID_ICE_ARGS=(--es stun_host "$STUN_HOST" --ei stun_port "$STUN_PORT")
fi
if (( USE_METERED == 1 )); then
    SIGNAL_ARGS=(--signal-metered "$METERED_API_KEY" "$METERED_CHANNEL")
    USING_EXISTING_RELAY=1
    PHONE_RELAY_HOST=""
    PHONE_RELAY_PORT=0
    say "Using Metered Realtime Messaging for signaling."
else
    SIGNAL_ARGS=(--signal-relay "$LINUX_RELAY_HOST" "$RELAY_PORT")
    say "Starting shared UDP signaling relay on port $RELAY_PORT..."
    : > "$RUN_DIR/relay.log"
    "$BOWIE_RELAY_BIN" 0.0.0.0 "$RELAY_PORT" >"$RUN_DIR/relay.log" 2>&1 &
    RELAY_PID=$!
    for ((i=0; i<START_TIMEOUT*5; i++)); do
        rg -q 'RELAY_STARTED' "$RUN_DIR/relay.log" && break
        if ! kill -0 "$RELAY_PID" 2>/dev/null; then
            wait "$RELAY_PID" 2>/dev/null || true
            RELAY_PID=""
            if rg -q 'errno=98' "$RUN_DIR/relay.log"; then
                USING_EXISTING_RELAY=1
                say "UDP $RELAY_PORT is already in use; using the existing relay."
            else
                cat "$RUN_DIR/relay.log" >&2
                fail "signal relay could not start on UDP $RELAY_PORT"
            fi
            break
        fi
        sleep 0.2
    done
    if (( USING_EXISTING_RELAY == 0 )); then
        rg -q 'RELAY_STARTED' "$RUN_DIR/relay.log" || fail "signal relay did not start"
    fi
fi
if [[ -n "$PHONE_RELAY_HOST" ]]; then
    ANDROID_RELAY_ARGS=(--es relay_host "$PHONE_RELAY_HOST" --ei relay_port "$PHONE_RELAY_PORT")
fi

say "Starting Linux TUN gateway through the relay..."
: > "$RUN_DIR/linux.log"
"${SUDO[@]}" env XDG_CONFIG_HOME="$RUN_DIR/linux-config" \
    "$BOWIE_BIN" listen "$TUN_NAME" "$LINUX_OVERLAY/24" \
    "${SIGNAL_ARGS[@]}" "${ICE_ARGS[@]}" "${TURN_ARGS[@]}" <&"$FIFO_FD" \
    >"$RUN_DIR/linux.log" 2>&1 &
LISTENER_PID=$!
if (( ${#TURN_ARGS[@]} > 0 )); then
    printf '%s\n%s\n' "$TURN_USERNAME" "$TURN_PASSWORD" >&"$FIFO_FD"
fi

linux_peer=""
signal_port=""
for ((i=0; i<START_TIMEOUT*5; i++)); do
    linux_peer="$(sed -n 's/^PEER_ID=//p' "$RUN_DIR/linux.log" | head -n1)"
    signal_port="$(sed -n 's/^SIGNAL_PORT=//p' "$RUN_DIR/linux.log" | head -n1)"
    [[ -n "$linux_peer" && -n "$signal_port" ]] && break
    "${SUDO[@]}" kill -0 "$LISTENER_PID" 2>/dev/null || { cat "$RUN_DIR/linux.log" >&2; fail "Linux listener exited early"; }
    sleep 0.2
done
[[ "$linux_peer" =~ ^[[:xdigit:]]{40}$ && "$signal_port" =~ ^[0-9]+$ ]] ||
    fail "Linux listener did not publish its peer ID and signal port"

"$ADB" logcat -b main -c || fail "could not clear stale Android app logs"
"$ADB" logcat -b main -v raw -s BowieJSON:I >"$RUN_DIR/android.log" 2>&1 &
LOGCAT_PID=$!
sleep 0.5
say "Preparing Android VPN; no peer IDs need to be copied."
"$ADB" shell am start -n org.bowie/.MainActivity -a org.bowie.TEST_PREPARE \
    --es host "$ANDROID_HOST" --ei port "$signal_port" --es peer_id "$linux_peer" \
    --es overlay_ip "$PHONE_OVERLAY" "${ANDROID_RELAY_ARGS[@]}" \
    "${ANDROID_ICE_ARGS[@]}" "${ANDROID_TURN_ARGS[@]}" \
    --es metered_api_key "$METERED_API_KEY" \
    --es metered_channel "$METERED_CHANNEL" >/dev/null

android_peer=""
for ((i=0; i<START_TIMEOUT*5; i++)); do
    ready="$(rg 'READY peer=[[:xdigit:]]{40}' "$RUN_DIR/android.log" | head -n1 || true)"
    android_peer="$(sed -nE 's/.*READY peer=([[:xdigit:]]{40}).*/\1/p' <<<"$ready")"
    [[ -n "$android_peer" ]] && break
    if rg -q 'VPN_SESSION_FAILED|"level":"ERROR"' "$RUN_DIR/android.log"; then
        cat "$RUN_DIR/android.log" >&2
        fail "Android VPN or engine startup failed (check whether Android requested VPN permission)"
    fi
    sleep 0.2
done
[[ "$android_peer" =~ ^[[:xdigit:]]{40}$ ]] || {
    say "Android did not become ready. If the system VPN consent prompt is showing, approve it once and rerun."
    cat "$RUN_DIR/android.log" >&2
    fail "Android app did not publish its peer ID"
}

say "Issuing a source grant for the Android peer..."
grant_output="$("${SUDO[@]}" env XDG_CONFIG_HOME="$RUN_DIR/linux-config" \
    "$BOWIE_BIN" grant "$android_peer" "$RUN_DIR/android.grant" --relay)" ||
    fail "Linux source could not issue the Android owner grant"
grant_hex="$(sed -n 's/^ANDROID_GRANT_HEX=//p' <<<"$grant_output")"
[[ "$grant_hex" =~ ^[[:xdigit:]]{304}$ ]] || fail "Linux source did not produce a valid Android grant"
# Grant timestamps have millisecond precision, while Android's date command
# may only expose whole seconds and its clock can lag Linux by a second. Wait
# until the phone clock has reached the signed issued_at before presenting it.
grant_issued_ms=$((16#${grant_hex:144:16}))
for ((i=0; i<10; i++)); do
    phone_now_s="$("$ADB" shell date +%s | tr -d '\r')"
    [[ "$phone_now_s" =~ ^[0-9]+$ ]] || fail "could not read Android clock while validating the owner grant"
    (( phone_now_s * 1000 >= grant_issued_ms )) && break
    sleep 1
done
(( phone_now_s * 1000 >= grant_issued_ms )) || fail "Android clock did not reach the owner grant issue time"

say "IDs exchanged automatically; confirming both relay registrations..."
registered=0
if (( USING_EXISTING_RELAY == 1 )); then
    registered=1
else
    for ((i=0; i<START_TIMEOUT*5; i++)); do
        if rg '"event":"PEER_REGISTERED"' "$RUN_DIR/relay.log" | grep -Fq "$linux_peer" &&
           rg '"event":"PEER_REGISTERED"' "$RUN_DIR/relay.log" | grep -Fq "$android_peer"; then
            registered=1
            break
        fi
        sleep 0.2
    done
fi
(( registered == 1 )) || {
    cat "$RUN_DIR/relay.log" >&2
    fail "the relay did not register both Linux and Android peers; check UDP $RELAY_PORT"
}
printf '%s\n' "$android_peer" >&"$FIFO_FD"
say "Waiting for Linux to pin the Android peer before connecting..."
for ((i=0; i<START_TIMEOUT*5; i++)); do
    rg -q 'ACCEPT_WAITING_FOR_SIGNAL' "$RUN_DIR/linux.log" && break
    "${SUDO[@]}" kill -0 "$LISTENER_PID" 2>/dev/null || { cat "$RUN_DIR/linux.log" >&2; fail "Linux listener exited before accepting"; }
    sleep 0.2
done
rg -q 'ACCEPT_WAITING_FOR_SIGNAL' "$RUN_DIR/linux.log" || fail "Linux listener did not enter authorized accept"
say "Linux is ready; starting the Android connector..."
"$ADB" shell am start -n org.bowie/.MainActivity -a org.bowie.TEST_CONNECT \
    --es host "$ANDROID_HOST" --ei port "$signal_port" --es peer_id "$linux_peer" \
    --es owner_grant "$grant_hex" \
    --es overlay_ip "$PHONE_OVERLAY" "${ANDROID_RELAY_ARGS[@]}" \
    "${ANDROID_ICE_ARGS[@]}" "${ANDROID_TURN_ARGS[@]}" \
    --es metered_api_key "$METERED_API_KEY" \
    --es metered_channel "$METERED_CHANNEL" >/dev/null
say "Waiting for authenticated connection..."
connected=0
for ((i=0; i<CONNECT_TIMEOUT*5; i++)); do
    if grep -q 'CONNECTED' "$RUN_DIR/linux.log" && rg -q '"status":"CONNECTED' "$RUN_DIR/android.log"; then
        connected=1
        break
    fi
    if rg -q '"level":"ERROR"|"status":"ERROR' "$RUN_DIR/android.log"; then
        cat "$RUN_DIR/android.log" >&2
        cat "$RUN_DIR/linux.log" >&2
        fail "Android reported a connection error"
    fi
    sleep 0.2
done
(( connected == 1 )) || {
    if ! rg -q 'received signal frame|SIGNAL_DESCRIPTION' "$RUN_DIR/linux.log"; then
        if (( USE_METERED == 1 )); then
            say "No Metered signaling offer reached Linux; inspect both peers' sanitized Metered diagnostics."
        else
            say "No relayed signaling packet reached Linux; check UDP $RELAY_PORT and the relay log."
        fi
    fi
    [[ ! -f "$RUN_DIR/relay.log" ]] || cat "$RUN_DIR/relay.log" >&2
    cat "$RUN_DIR/linux.log" >&2
    cat "$RUN_DIR/android.log" >&2
    fail "Linux and Android did not complete the authenticated handshake"
}

say "PASS: Linux userspace gateway test passed and Android authenticated to the Linux peer."
say "Sending a real Android ping through the VPN TUN to $PING_TARGET..."
if ! "$ADB" shell ping -c 3 -W 4 "$PING_TARGET" >"$RUN_DIR/android-ping.log" 2>&1; then
    cat "$RUN_DIR/android-ping.log" >&2
    cat "$RUN_DIR/linux.log" >&2
    fail "Android overlay ping failed"
fi
cat "$RUN_DIR/android-ping.log"
if ! rg -q 'GATEWAY_PACKET_FORWARDED.*"direction":"out"' "$RUN_DIR/linux.log" ||
   ! rg -q 'GATEWAY_PACKET_FORWARDED.*"direction":"in"' "$RUN_DIR/linux.log"; then
    say "Waiting briefly for Linux to flush its gateway counters..."
    sleep 5
fi
if ! rg -q 'GATEWAY_PACKET_FORWARDED.*"direction":"out"' "$RUN_DIR/linux.log" ||
   ! rg -q 'GATEWAY_PACKET_FORWARDED.*"direction":"in"' "$RUN_DIR/linux.log"; then
    cat "$RUN_DIR/linux.log" >&2
    fail "ping returned without observing packets in both Linux TUN gateway directions"
fi
say "PASS: real Android overlay ping crossed the Linux and Android TUN gateways."
if [[ -n "$OPEN_URL" ]]; then
    say "Opening the requested HTTPS site on Android while the tunnel is active."
    "$ADB" shell am start -a android.intent.action.VIEW -d "$OPEN_URL" >/dev/null ||
        fail "Android could not open the requested HTTPS site"
    say "Keeping the connected tunnel active for ${OPEN_SECONDS}s while the page loads."
    sleep "$OPEN_SECONDS"
elif (( HOLD_SECONDS > 0 )); then
    say "Tunnel is ready; open apps on the phone now. It will remain connected for ${HOLD_SECONDS}s."
    sleep "$HOLD_SECONDS"
fi
