#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
LOSS_PERCENT="${LOSS_PERCENT:-10}"
PING_COUNT="${PING_COUNT:-30}"
PING_SIZE="${PING_SIZE:-1472}"

exec env LOSS_PERCENT="$LOSS_PERCENT" PING_COUNT="$PING_COUNT" PING_SIZE="$PING_SIZE" \
    "$ROOT_DIR/tests/e2e/test_loopback.sh" "$@"
