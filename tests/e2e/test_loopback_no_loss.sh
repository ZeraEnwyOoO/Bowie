#!/usr/bin/env bash
set -Eeuo pipefail

# Baseline counterpart to test_packet_loss.sh. Uses the same full-size ping
# defaults with netem disabled, so its result can be compared with the lossy run.
ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
PING_COUNT="${PING_COUNT:-30}"
PING_SIZE="${PING_SIZE:-1472}"

exec env LOSS_PERCENT=0 PING_COUNT="$PING_COUNT" PING_SIZE="$PING_SIZE" \
    "$ROOT_DIR/tests/e2e/test_loopback.sh" "$@"
